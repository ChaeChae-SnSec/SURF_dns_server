# doh_proxy.py
#
# RFC 8484 DoH 종단. 크롬의 "보안 DNS 사용 - 맞춤 설정"에 이 주소를 넣으면
# 브라우저 질의가 여기로 들어온다.
#
#   https://dns.example.com/dns-query?c=<클라이언트 토큰>
#
# 존재 이유가 두 가지다.
#
#  1) 도달성. Cloudflare 터널이 아웃바운드 연결만 쓰므로 사설망에 있는 DNS 서버를
#     포트 개방 없이 밖에서 쓸 수 있다. 발표장 와이파이가 무엇이든 상관없어진다.
#
#  2) 클라이언트 식별. 터널을 지나면 소스 주소가 전부 127.0.0.1 로 뭉개져 기기를
#     구분할 수 없다. 토큰마다 127.x.y.z 를 하나씩 배정해 그 주소를 소스로 질의를
#     보내고, 매핑을 Redis 에 남긴다. Unbound 모듈이 resolve_client_id 에서 이걸
#     되읽어 토큰으로 바꾸므로 확장·HTTP 서버와 같은 키로 묶인다.
#
# DNS 메시지는 해석하지 않고 바이트 그대로 넘긴다. 판별은 Unbound 안의 모듈이 한다.

from dotenv import load_dotenv
load_dotenv()

import base64
import hashlib
import os
import socket
import struct
import time

from flask import Flask, request, Response, jsonify
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import redis

UNBOUND_HOST = os.getenv('UNBOUND_HOST', '127.0.0.1')
UNBOUND_PORT = int(os.getenv('UNBOUND_PORT', '53'))
UDP_TIMEOUT = float(os.getenv('DOH_UDP_TIMEOUT', '3.0'))
TOKMAP_TTL = int(os.getenv('TOKMAP_TTL', '604800'))      # 7일
MAX_BODY = 65535
DNS_CONTENT_TYPE = 'application/dns-message'

app = Flask(__name__)

R_CONN = redis.StrictRedis(
    host=os.getenv('REDIS_HOST', '127.0.0.1'),
    port=int(os.getenv('REDIS_PORT', '6379')),
    db=int(os.getenv('REDIS_DB', '0')),
    decode_responses=True
)

PRECISION_BUCKETS = (.0005, .001, .002, .005, .01, .025, .05, .075, .1,
                     .25, .5, 1.0, 2.5, 5.0, float("inf"))

DOH_QUERIES = Counter('surf_doh_queries_total', 'DoH queries', ['method', 'transport'])
DOH_ERRORS = Counter('surf_doh_errors_total', 'DoH failures', ['reason'])
DOH_LATENCY = Histogram('surf_doh_duration_seconds', 'DoH round trip',
                        buckets=PRECISION_BUCKETS)

# ---------------------------------------------------------------- 토큰 -> 소스 주소

def synthetic_ip(token):
    """토큰에서 고정된 루프백 주소를 만든다.

    리눅스는 127.0.0.0/8 전체를 lo 의 local 라우트로 잡고 있어서 별도 설정 없이
    이 대역 어디에나 바인딩할 수 있다. 127.0.0.1 과 겹치지 않도록 두 번째 옥텟을
    1 이상으로 둔다. 주소 공간이 1600만이라 파일럿 규모에서 충돌은 사실상 없다.
    """
    h = hashlib.sha256(token.encode('utf-8')).digest()
    return f"127.{1 + h[0] % 254}.{h[1]}.{1 + h[2] % 254}"


def register_token(token):
    src = synthetic_ip(token)
    try:
        # 질의마다 갱신한다. 쓰는 동안에는 매핑이 만료되지 않는다.
        R_CONN.setex(f"tokmap:{src}", TOKMAP_TTL, token)
    except Exception as e:
        app.logger.warning(f"tokmap 저장 실패: {e}")
    return src

# ---------------------------------------------------------------- 업스트림 전달

def forward_udp(payload, src_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((src_ip, 0))
        sock.settimeout(UDP_TIMEOUT)
        sock.sendto(payload, (UNBOUND_HOST, UNBOUND_PORT))
        return sock.recv(4096)
    finally:
        sock.close()


def forward_tcp(payload, src_ip):
    """UDP 응답이 잘렸을 때 쓴다. TCP 는 길이 2바이트를 앞에 붙인다."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((src_ip, 0))
        sock.settimeout(UDP_TIMEOUT)
        sock.connect((UNBOUND_HOST, UNBOUND_PORT))
        sock.sendall(struct.pack('!H', len(payload)) + payload)

        header = b''
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk:
                raise ConnectionError('길이 헤더를 받지 못했다')
            header += chunk

        remaining = struct.unpack('!H', header)[0]
        body = b''
        while len(body) < remaining:
            chunk = sock.recv(remaining - len(body))
            if not chunk:
                raise ConnectionError('응답이 중간에 끊겼다')
            body += chunk
        return body
    finally:
        sock.close()


def is_truncated(msg):
    # 헤더 세 번째 바이트의 TC 비트
    return len(msg) >= 3 and bool(msg[2] & 0x02)

# ---------------------------------------------------------------- 라우트

@app.route('/dns-query', methods=['GET', 'POST'])
@app.route('/dns-query/<path:path_token>', methods=['GET', 'POST'])
def dns_query(path_token=None):
    """RFC 8484 종단.

    토큰을 두 가지 방법으로 받는다.

        /dns-query?c=<토큰>        쿼리 문자열
        /dns-query/<토큰>          경로

    크롬의 보안 DNS 설정은 입력한 주소를 URI 템플릿으로 다루는데, 쿼리 문자열이
    이미 붙어 있으면 거부하는 경우가 있다. 경로 방식이면 그 문제가 없다.
    """
    started = time.time()

    if request.method == 'POST':
        if request.content_type != DNS_CONTENT_TYPE:
            DOH_ERRORS.labels(reason='bad_content_type').inc()
            return Response('unsupported content type', status=415)
        payload = request.get_data(cache=False)
    else:
        encoded = request.args.get('dns')
        if not encoded:
            DOH_ERRORS.labels(reason='missing_dns_param').inc()
            return Response('missing dns parameter', status=400)
        try:
            # base64url. 패딩이 생략되어 오므로 채워서 디코딩한다.
            payload = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
        except Exception:
            DOH_ERRORS.labels(reason='bad_base64').inc()
            return Response('malformed dns parameter', status=400)

    if not payload or len(payload) < 12 or len(payload) > MAX_BODY:
        DOH_ERRORS.labels(reason='bad_length').inc()
        return Response('malformed dns message', status=400)

    token = (path_token or request.args.get('c') or 'anon').strip()[:64]
    src_ip = register_token(token)

    transport = 'udp'
    try:
        answer = forward_udp(payload, src_ip)
        if is_truncated(answer):
            transport = 'tcp'
            answer = forward_tcp(payload, src_ip)
    except socket.timeout:
        DOH_ERRORS.labels(reason='upstream_timeout').inc()
        return Response('upstream timeout', status=504)
    except Exception as e:
        app.logger.warning(f"업스트림 전달 실패: {e}")
        DOH_ERRORS.labels(reason='upstream_error').inc()
        return Response('upstream failure', status=502)

    DOH_QUERIES.labels(method=request.method, transport=transport).inc()
    DOH_LATENCY.observe(time.time() - started)

    # 캐시는 리졸버가 관리한다. 중간 캐시가 끼면 차단 반영이 늦어진다.
    return Response(answer, mimetype=DNS_CONTENT_TYPE,
                    headers={'Cache-Control': 'no-store'})


@app.route('/healthz')
def healthz():
    """터널 감시용. 업스트림까지 실제로 물어본다."""
    # google.com A 질의 한 건을 만들어 왕복을 확인한다.
    probe = (struct.pack('!HHHHHH', 0x5552, 0x0100, 1, 0, 0, 0)
             + b'\x06google\x03com\x00' + struct.pack('!HH', 1, 1))
    try:
        answer = forward_udp(probe, synthetic_ip('__healthz__'))
        ok = len(answer) >= 12
    except Exception as e:
        return jsonify({"status": "degraded", "upstream": str(e)}), 503

    try:
        R_CONN.ping()
    except Exception as e:
        return jsonify({"status": "degraded", "redis": str(e)}), 503

    return jsonify({"status": "ok" if ok else "degraded"}), (200 if ok else 503)


@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


if __name__ == '__main__':
    port = int(os.getenv('DOH_PORT', '8053'))
    print(f"🚀 DoH 프록시 개발 서버 시작 (port {port}). 배포에는 gunicorn 을 쓰세요.", flush=True)
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False)
