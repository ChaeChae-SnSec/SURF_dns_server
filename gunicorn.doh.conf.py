# gunicorn.doh.conf.py
#
#   gunicorn -c gunicorn.doh.conf.py doh_proxy:app
#
# 소켓 왕복만 하는 일이라 대기 시간이 대부분이고, 파이썬은 소켓 I/O 중 GIL 을
# 놓기 때문에 스레드만으로 충분하다. 워커를 1개로 두는 것은 HTTP 서버 쪽과 같은
# 이유다. prometheus_client 가 프로세스별로 집계해서 워커가 여럿이면 /metrics 가
# 매번 다른 숫자를 내놓는다.
#
# 브라우저의 모든 이름 해석이 여기를 지나므로 지연이 그대로 체감된다.
# 타임아웃을 짧게 잡아 멈춘 요청이 스레드를 오래 붙들지 않게 한다.

import os

bind = f"127.0.0.1:{os.getenv('DOH_PORT', '8053')}"
workers = int(os.getenv('DOH_WORKERS', '1'))
threads = int(os.getenv('DOH_THREADS', '16'))
worker_class = 'gthread'

timeout = 20
graceful_timeout = 10
keepalive = 65          # 크롬이 DoH 연결을 오래 유지한다

accesslog = None        # 질의마다 한 줄씩 쌓이면 디스크만 먹는다
errorlog = '-'
loglevel = os.getenv('DOH_LOGLEVEL', 'warning')
