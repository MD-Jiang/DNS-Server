FROM python:3.12-slim-bookworm

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

ENV DNS_SERVER_HOST=dns_server \
    DNS_SERVER_PORT=2053 \
    PROXY_PORT=5353 \
    HTTP_PORT=8080 \
    DNS_PROC_NAME=dns_server

EXPOSE 8080/tcp
EXPOSE 5353/udp

CMD ["python", "-m", "uvicorn", "backend.app:app", \
     "--host", "0.0.0.0", "--port", "8080"]
