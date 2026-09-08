# surf_unbound.py

from dotenv import load_dotenv
load_dotenv()

import os
import sys

# 환경변수가 비어 있으면 sys.path 에 None 이 들어간다. 그러면 나중에
# importlib.metadata 가 경로를 stat 하다가 TypeError 로 죽는데, 파이썬 모듈이
# 로드되지 않아 unbound 자체가 기동하지 못한다.
VENV_PATH = os.getenv('VENV_PATH')
if VENV_PATH and VENV_PATH not in sys.path:
    sys.path.insert(0, VENV_PATH)

PROJECT_ROOT = os.getenv('PROJECT_ROOT')
if PROJECT_ROOT and PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from prometheus_client import Counter, Histogram, Gauge, start_http_server
from SURF_AI_model.model_setting import DomainClassifier
import time
import redis
import json

# 메트릭 정의
PRECISION_BUCKETS = (.0005, .001, .002, .005, .01, .025, .05, .075, .1, .25, .5, 1.0, 2.5, 5.0, float("inf"))

DNS_QUERIES = Counter('surf_dns_queries_total', 
                        'Total DNS queries', 
                        ['client_ip', 'qtype', 'result'])
BLOCKED_LOG = Counter('surf_dns_blocked_total', 
                        'Total blocked DNS queries', 
                        ['domain', 'client_ip'])
# 전체 처리 시간 (AI + 로직)
TOTAL_LATENCY = Histogram('surf_dns_total_duration_seconds', 
                            'Total processing latency', 
                            ['prediction'], 
                            buckets=PRECISION_BUCKETS)
# 순수 AI 모델 추론 시간
AI_LATENCY = Histogram('surf_ai_inference_duration_seconds', 
                        'Pure AI inference latency', 
                        ['prediction'], 
                        buckets=PRECISION_BUCKETS)
WHITELIST_HITS = Counter('surf_dns_whitelist_hits_total', 
                        'Whitelist bypass counts', 
                        ['domain', 'client_ip'])
ALLOWED_LOG = Counter('surf_dns_allowed_total', 
                        'Total allowed DNS queries', 
                        ['domain', 'client_ip'])
DNS_STAGES_LATENCY = Histogram('surf_dns_stage_duration_seconds', 
                            'Latency of DNS processing stages', 
                            ['stage', 'res_label'], 
                            buckets=PRECISION_BUCKETS
                        )
LAST_SEEN_TIME = Gauge('surf_dns_last_seen_seconds', 
                        'Last seen timestamp for domain', 
                        ['domain', 'result'])
DNS_UPSTREAM_RESOLVE_TOTAL = Counter('surf_dns_upstream_resolve_total',
                        'Final resolution status for AI-allowed queries',
                        ['status']  # 'success', 'nxdomain', 'error'
                    )

try:
    start_http_server(int(os.getenv('PROMETHEUS_PORT')))
except Exception:
    pass

R_CONN = redis.StrictRedis(host=os.getenv('REDIS_HOST'), port=int(os.getenv('REDIS_PORT')), db=int(os.getenv('REDIS_DB')), decode_responses=True)

print("====================================================", flush=True)
print("🚀 PYTHON SCRIPT LOADED SUCCESSFULLY!", flush=True)
print(f"PYTHON VERSION: {sys.version}", flush=True)
print("====================================================", flush=True)

WHITELIST = [
    "microsoft.com",        # 마이크로소프트 기본
    "windows.com",          # 윈도우 시스템
    "windowsupdate.com",    # 윈도우 업데이트 (필수!)
    "office.com",           # 오피스 365
    "office365.com",        # 오피스 계정 관련
    "officeppe.com",        # 오피스 개발/환경 관련
    "microsoftonline.com",  # 마이크로소프트 로그인
    "msftconnecttest.com",  # 윈도우 인터넷 연결 확인 (오탐 1순위)
    "msn.com",              # MSN 및 엣지 브라우저 뉴스
    "bing.com",             # 빙 검색 및 이미지
    "azure.com",            # 애저 클라우드 서비스
    "msftncsi.com",         # 윈도우 인터넷 연결 확인 (오탐 1순위)

    "lencr.org",            # Let's Encrypt (무료 보안인증서 필수 주소)
    "pki.goog",             # 구글 보안 인증서
    "nist.gov",             # NIST 표준 시간 동기화 (컴퓨터 시계용)

    "akamai.net",           
    "akamaized.net",
    "edgekey.net",
    "akamaiedge.net",
    "edgesuite.net",
    "fastly.net",
    "trafficmanager.net",   # 마이크로소프트 서비스 연결 최적화
    "ax-msedge.net",        # 엣지 브라우저 최적화

    "mcafee.com",           # 맥아피 백신 업데이트
    "mcafee.net"
]

def resolve_client_id(client_ip):
    """클라이언트 식별자를 정한다.

    DoH 를 거쳐 들어온 질의는 소스 주소가 프록시의 루프백 주소다. 프록시가
    토큰마다 127.x.y.z 를 하나씩 배정하고 tokmap 에 매핑을 남기므로, 여기서
    되읽어 토큰으로 바꾼다. 그래야 Redis 키가 확장·HTTP 서버와 같은 값으로
    묶인다. 랩 안에서 직접 붙은 질의는 매핑이 없으니 IP 를 그대로 쓴다.
    """
    if not client_ip.startswith("127."):
        return client_ip
    try:
        token = R_CONN.get(f"tokmap:{client_ip}")
        if token:
            return token
    except Exception as e:
        log_info(f"⚠️ tokmap 조회 실패: {e}")
    return client_ip


RECENT_LIST_MAX = 49  # LTRIM 상한. 0부터 세므로 실제로는 50건 보관


def push_recent(client_ip, domain, blocked, prob):
    """최근 판정을 Redis 링버퍼(recent:dns)에 남긴다.

    Grafana의 '최신 DNS 질의' 표가 여기서 읽는다. 화이트리스트로 곧장 통과한
    질의는 모델이 실제로 판정한 게 아니므로 넣지 않는다 - 대시보드의 '판정 질의'
    지표와 의미를 맞춘다.
    """
    try:
        entry = json.dumps({
            "ts": time.time(),
            "client": client_ip,
            "domain": domain,
            "blocked": bool(blocked),
            "prob": prob,
        })
        R_CONN.lpush("recent:dns", entry)
        R_CONN.ltrim("recent:dns", 0, RECENT_LIST_MAX)
    except Exception as e:
        log_info(f"⚠️ recent 기록 실패: {e}")


def init(id, cfg):
    log_info("SURF AI Filter: DomainClassifier loading...")
    mod_env['model'] = DomainClassifier()
    return True

def operate(id, event, qstate, qdata):
    if event == MODULE_EVENT_NEW:
        start_total = time.time()

        client_ip = "unknown"
        try:
            r_list = getattr(qstate, 'reply_list', 
                     getattr(qstate.mesh_info, 'reply_list', None) if hasattr(qstate, 'mesh_info') else None)

            if r_list:
                log_info("📂 [PATH A] mesh_reply 발견!")
                if hasattr(r_list, 'query_reply') and r_list.query_reply:
                    q_reply = r_list.query_reply
                    client_ip = getattr(q_reply, 'addr', getattr(q_reply, 'client_addr', str(q_reply)))
                else:
                    log_info("  ⚠️ mesh_reply는 있으나 query_reply 속성이 없음")
            
            if client_ip == "unknown" or "object" in client_ip:
                log_info("📂 [PATH B] qstate.reply 직접 추적 시도...")
                if hasattr(qstate, 'reply') and qstate.reply:
                    r_obj = qstate.reply
                    log_info(f"  👉 reply 속성 발견: {dir(r_obj)}")
                    client_ip = getattr(r_obj, 'addr', getattr(r_obj, 'client_addr', str(r_obj)))
                    log_info(f"  🎯 [PATH B SUCCESS] Raw IP: {client_ip}")
                else:
                    log_info("  ❌ [PATH B FAIL] qstate.reply 속성도 없음")

        except Exception as e:
            log_info(f"💥 [DEBUG ERROR] 추적 중 사고 발생: {str(e)}")

        client_ip = str(client_ip)
        if "::ffff:" in client_ip:
            client_ip = client_ip.replace("::ffff:", "")
        client_ip = client_ip.split(' ')[0].split('@')[0].split('#')[0].strip()

        client_ip = resolve_client_id(client_ip)

        log_info(f"🔍 [FINAL IP CHECK] Client ID: {client_ip}")

        qtype_str = "A" if qstate.qinfo.qtype == RR_TYPE_A else "AAAA"

        qdata['client_ip'] = client_ip
        qdata['qtype_str'] = qtype_str
        qdata['start_total'] = start_total
        qdata['res_label'] = "none" # 초기값 설정

        start_logic = time.time() # 전처리 시작
        full_qname = qstate.qinfo.qname_str
        qname = full_qname.rstrip('.')
        predict_name = qname[4:] if qname.startswith("www.") else qname

        log_info(f"--- 🌐[[DEBUG]] Python Module Caught Query: {qname} {qtype_str} ---")
        start_time = time.time()

        if qstate.qinfo.qtype not in [RR_TYPE_A, RR_TYPE_AAAA]:
            DNS_QUERIES.labels(client_ip=client_ip, qtype=qtype_str, result="ignored").inc()
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

        if qname.endswith(".local") or qname.startswith("_") or ".arpa" in qname:
            DNS_QUERIES.labels(client_ip=client_ip, qtype=qtype_str, result="ignored").inc()
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

        try:
            if client_ip != 'unknown':
                if R_CONN.exists(f"whitelist:{client_ip}:{predict_name}"):
                    log_info(f"⚪ [IP-PERM WHITELIST]: {client_ip} -> {qname}")
                    DNS_QUERIES.labels(client_ip=client_ip, qtype=qtype_str, result="whitelist").inc()
                    qstate.ext_state[id] = MODULE_WAIT_MODULE
                    return True

                if R_CONN.exists(f"allow:{client_ip}:{predict_name}"):
                    log_info(f"🟡 [TEMP ALLOW]: {client_ip} -> {qname}")
                    DNS_QUERIES.labels(client_ip=client_ip, qtype=qtype_str, result="whitelist").inc()
                    qstate.ext_state[id] = MODULE_WAIT_MODULE
                    return True
        except Exception as e:
            log_info(f"⚠️ Redis Whitelist Check Error: {e}")

        if any(qname.endswith(suffix) for suffix in WHITELIST):
            log_info(f"✅ [WHITELIST PASS]: {qname}")
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            DNS_QUERIES.labels(client_ip=client_ip, qtype=qtype_str, result="whitelist").inc()
            WHITELIST_HITS.labels(domain=qname, client_ip=client_ip).inc()
            LAST_SEEN_TIME.labels(domain=qname, result="whitelist").set(time.time())
            return True
        
        DNS_STAGES_LATENCY.labels(stage='logic_check', res_label='processing').observe(time.time() - start_logic)

        model = mod_env['model']
        start_ai = time.time()
        pred, probs = model.predict(predict_name)
        ai_dur = time.time() - start_ai

        r_per = probs[0][1].item() * 100
        s_per = round((r_per - 50) * 2, 2)

        res_label = "blocked" if pred == 1 else "allowed"
        qdata['res_label'] = res_label
        
        AI_LATENCY.labels(prediction=res_label).observe(ai_dur)
        DNS_STAGES_LATENCY.labels(stage='ai_inference', res_label=res_label).observe(ai_dur)
        TOTAL_LATENCY.labels(prediction=res_label).observe(time.time() - start_total)

        log_info(f"--- [[DEBUG]] Prediction for {qname}) ===> {pred} ---")
        DNS_QUERIES.labels(client_ip=client_ip, qtype=qtype_str, result=res_label).inc()
        push_recent(client_ip, qname, pred == 1, max(0.0, s_per))

        start_resp = time.time()
        if pred == 1:
            BLOCKED_LOG.labels(domain=qname, client_ip=client_ip).inc() # Prometheus: 차단 카운터 증가
            LAST_SEEN_TIME.labels(domain=qname, result="blocked").set(time.time())

            r_key = f"dns_time:{client_ip}:{predict_name}"
            R_CONN.setex(r_key, 10, time.time()) # 10초만 유지

            R_CONN.setex(f"block_mark:{client_ip}:{predict_name}", 300, str(s_per))

            # 도메인 단위로도 짧게 남긴다.
            #
            # 클라이언트를 어느 이름으로 보는지가 경로마다 다르다. DoH 로 들어오면
            # 토큰이지만 53 에 직접 붙으면 IP 다. 그런데 확장이 /check 를 호출할 때
            # 터널을 지나면 그 IP 가 사라져서, 53 직결로 막힌 기기는 자기 기록을
            # 찾지 못한다. 그 간극을 메우는 자리다.
            #
            # 판정은 도메인만 보고 하므로 같은 도메인이면 누구에게나 같은 결과다.
            # 창을 60초로 좁혀 두어 오래된 판정이 남지 않게 한다.
            R_CONN.setex(f"block_recent:{predict_name}", 60, str(s_per))

            log_info(f"🚨 [SURF BLOCKED] {qname}")
            
            msg = DNSMessage(full_qname, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_AA | PKT_RA)
            
            if not msg.set_return_msg(qstate):
                log_info("❌ Failed to set return message")
                qstate.ext_state[id] = MODULE_ERROR
                return True
            
            if qstate.return_msg and qstate.return_msg.rep:
                qstate.return_msg.rep.security = 2  # 2 = sec_status_insecure
                qstate.return_msg.rep.authoritative = 1 # 이 서버가 최종 권한자임을 명시
            
            qstate.return_rcode = RCODE_NXDOMAIN
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        elif pred == 0:
            log_info(f"✅ [SURF AI ALLOWED] {qname}")
            ALLOWED_LOG.labels(domain=qname, client_ip=client_ip).inc()
            LAST_SEEN_TIME.labels(domain=qname, result="allowed").set(time.time())
            qstate.ext_state[id] = MODULE_WAIT_MODULE
        
        DNS_STAGES_LATENCY.labels(stage='packet_gen', res_label=res_label).observe(time.time() - start_resp)
        DNS_STAGES_LATENCY.labels(stage='total_dns', res_label=res_label).observe(time.time() - start_total)
        
        return True
        
    elif event == MODULE_EVENT_MODDONE:
        try:
            cip = qdata.get('client_ip', "unknown")
            res_label = qdata.get('res_label', "none")

            if res_label == "allowed":
                status = "success"
                if qstate.return_rcode == RCODE_NXDOMAIN:
                    status = "nxdomain"
                elif qstate.return_rcode != RCODE_NOERROR:
                    status = "error"
                
                DNS_UPSTREAM_RESOLVE_TOTAL.labels(status=status).inc()
                
        except Exception as e:
            log_info(f"MODDONE LOGGING ERROR: {e}")

        qstate.ext_state[id] = MODULE_FINISHED
        return True

    qstate.ext_state[id] = MODULE_WAIT_MODULE
    return True

def deinit(id):
    return True

def inform_super(id, qstate, super_qstate, qdata):
    """부모 쿼리 상태에 대한 정보를 받을 때 호출되는 함수 (필수)"""
    return True

def clear(id):
    """상태를 초기화할 때 호출"""
    return True