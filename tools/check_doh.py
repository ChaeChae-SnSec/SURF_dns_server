"""doh_proxy 의 실제 함수를 로컬 리졸버(127.0.0.53) 상대로 검증한다."""
import sys, types, os, base64, struct

# flask / redis 를 스텁으로 채워 doh_proxy 를 그대로 임포트한다.
flask = types.ModuleType('flask')
class _App:
    def __init__(self, *a, **k):
        self.logger = types.SimpleNamespace(warning=lambda m: print(f"  [warn] {m}"))
    def route(self, *a, **k):
        return lambda f: f
flask.Flask = _App
flask.Response = lambda *a, **k: None
flask.request = None
flask.jsonify = lambda *a, **k: None
sys.modules['flask'] = flask

redis = types.ModuleType('redis')
class _R:
    def __init__(self, *a, **k): pass
    def setex(self, *a): raise RuntimeError("redis 미구동 (의도된 상황)")
    def ping(self): raise RuntimeError("redis 미구동")
redis.StrictRedis = _R
sys.modules['redis'] = redis

os.environ.setdefault('UNBOUND_HOST', '127.0.0.1')
os.environ['UNBOUND_PORT'] = '53'

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import doh_proxy as D
import dns.message

fails = []

# 1) 토큰 -> 소스 주소가 결정적이고 127.0.0.1 을 피하는지
a1, a2 = D.synthetic_ip('demo01'), D.synthetic_ip('demo01')
a3 = D.synthetic_ip('demo02')
print(f"1) demo01 -> {a1} / demo02 -> {a3}")
if a1 != a2: fails.append("동일 토큰이 다른 주소를 냄")
if a1 == a3: fails.append("다른 토큰이 같은 주소로 충돌")
if any(D.synthetic_ip(f"t{i}") == '127.0.0.1' for i in range(3000)):
    fails.append("127.0.0.1 과 충돌하는 토큰 존재")
print("   ✅ 결정적 / 127.0.0.1 회피" if not fails else f"   ❌ {fails}")

# 2) Redis 가 죽어도 register_token 이 주소를 돌려주는지 (fail-open)
try:
    src = D.register_token('demo01')
    print(f"2) redis 장애 시에도 소스 주소 반환: {src}")
    print("   ✅ fail-open 동작")
except Exception as e:
    fails.append(f"register_token 이 예외를 던짐: {e}")
    print(f"   ❌ {e}")

# 3) 소스 바인딩 UDP 질의가 실제로 왕복하는지
q = dns.message.make_query('google.com', 'A').to_wire()
try:
    ans = D.forward_udp(q, D.synthetic_ip('demo01'))
    parsed = dns.message.from_wire(ans)
    n = len(parsed.answer)
    print(f"3) UDP 왕복 성공, 응답 {len(ans)}바이트 / answer {n}개")
    print("   ✅ 통과" if n > 0 else "   ⚠️ answer 없음")
    if n == 0: fails.append("UDP 응답에 answer 없음")
except Exception as e:
    fails.append(f"UDP 왕복 실패: {e}")
    print(f"3) ❌ {e}")

# 4) TCP 경로 (잘린 응답 대체 경로)
try:
    ans = D.forward_tcp(q, D.synthetic_ip('demo01'))
    parsed = dns.message.from_wire(ans)
    print(f"4) TCP 왕복 성공, 응답 {len(ans)}바이트 / answer {len(parsed.answer)}개")
    print("   ✅ 통과")
except Exception as e:
    fails.append(f"TCP 왕복 실패: {e}")
    print(f"4) ❌ {e}")

# 5) TC 비트 판정
notrunc = dns.message.make_query('google.com', 'A')
trunc = dns.message.make_query('google.com', 'A')
trunc.flags |= 0x0200
print(f"5) TC 판정: 정상={D.is_truncated(notrunc.to_wire())} 잘림={D.is_truncated(trunc.to_wire())}")
if D.is_truncated(notrunc.to_wire()) or not D.is_truncated(trunc.to_wire()):
    fails.append("TC 비트 판정 오류")
    print("   ❌ 오판")
else:
    print("   ✅ 통과")

# 6) healthz 가 손으로 만든 질의 패킷이 유효한지
probe = (struct.pack('!HHHHHH', 0x5552, 0x0100, 1, 0, 0, 0)
         + b'\x06google\x03com\x00' + struct.pack('!HH', 1, 1))
try:
    pm = dns.message.from_wire(probe)
    print(f"6) healthz 프로브 파싱: {pm.question[0]}")
    ans = D.forward_udp(probe, D.synthetic_ip('__healthz__'))
    print(f"   응답 {len(ans)}바이트 -> ✅ 통과")
except Exception as e:
    fails.append(f"healthz 프로브 실패: {e}")
    print(f"6) ❌ {e}")

# 7) base64url 패딩 복원 (크롬 GET 경로)
enc = base64.urlsafe_b64encode(q).decode().rstrip('=')
dec = base64.urlsafe_b64decode(enc + '=' * (-len(enc) % 4))
print(f"7) base64url 무패딩 복원: {'✅ 일치' if dec == q else '❌ 불일치'}")
if dec != q: fails.append("base64url 복원 실패")

print()
print("=" * 46)
print("✅ 전부 통과" if not fails else f"❌ 실패 {len(fails)}건: {fails}")
