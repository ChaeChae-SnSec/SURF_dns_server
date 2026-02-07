from dnslib import DNSRecord

def send_real_dns_query():
    # DNS 쿼리 생성 (naver.com을 물어보는 패킷)
    q = DNSRecord.question("ubuntu.com")
    packet = q.pack()

    # UDP로 서버(10053 포트)에 전송
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print("📡 서버(127.0.0.1:10053)로 진짜 DNS 패킷을 보냅니다...")
    sock.sendto(packet, ("127.0.0.1", 10053))
    
    # 서버 응답 기다리기 (선택 사항)
    sock.settimeout(2)
    try:
        data, _ = sock.recvfrom(1024)
        print("✅ 서버로부터 응답을 받았습니다!")
        print(DNSRecord.parse(data))
    except Exception as e:
        print(f"⚠️ 응답 대기 중 오류: {e} (서버 로그를 확인하세요)")
    finally:
        sock.close()

if __name__ == "__main__":
    send_real_dns_query()