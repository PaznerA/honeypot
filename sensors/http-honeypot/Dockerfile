FROM python:3.12-slim

# Neinteraktivní, bez cache, běh pod neprivilegovaným uživatelem.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HONEYPOT_PORT=8080 \
    HONEYPOT_LOG=/var/log/honeypot/http.json

RUN useradd --system --uid 10001 --no-create-home honeypot \
    && mkdir -p /var/log/honeypot \
    && chown honeypot:honeypot /var/log/honeypot

WORKDIR /app
COPY app.py /app/app.py

USER honeypot
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import socket,os; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', int(os.environ['HONEYPOT_PORT']))); s.close()" || exit 1

ENTRYPOINT ["python", "/app/app.py"]
