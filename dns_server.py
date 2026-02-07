from dnslib.server import DNSServer, BaseResolver
from dnslib import DNSRecord, QTYPE
from dnslib import RR, A
import time
from model_setting import DomainClassifier

BLOCK_IP = "127.0.0.1"

class SimpleResolver(BaseResolver):
    def __init__(self):
        self.model = DomainClassifier()

    def resolve(self, request, handler):

        client_ip = handler.client_address[0]
        qname = str(request.q.qname).rstrip('.')
        print(f"🔍 [QUERY] Received request for: {qname} from {client_ip}")

        # 기본 reply 생성 (ID 유지)
        reply = request.reply()

        # Query 타입 필터 (제일 먼저)
        qtype = QTYPE[request.q.qtype]

        # 웹 접속용(A/AAAA)만 처리
        if qtype not in ("A", "AAAA"):
            return reply

        # domain 추출
        qname = request.q.qname
        domain = str(qname).rstrip('.')

        # mDNS / local 도메인 필터링
        if (
            domain.endswith(".local")
            or domain.startswith("_")
            or domain.endswith(".arpa")
        ):
            return reply

        # 전처리 (www 제거)
        if domain.startswith("www."):
            domain = domain[4:]

        pred, _ = self.model.predict(domain)

        if pred == 1:
            print(f"[BLOCKED] {domain} → {BLOCK_IP}")
            reply = request.reply()

            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=60,
                    rdata=A(BLOCK_IP),
                )
            )
            return reply

        # 정상 도메인 → 실제 DNS로 포워딩
        try:
            proxy_reply = request.send("8.8.8.8", 53, timeout=2)
            reply = DNSRecord.parse(proxy_reply)
        except Exception as e:
            print("DNS forwarding failed:", e)

        return reply

if __name__ == "__main__":
    resolver = SimpleResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0")

    print("🚀 DNS server running on port 10053")
    server.start_thread()

    while True:
        time.sleep(1)
