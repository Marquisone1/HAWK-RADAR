# ---------- builder ----------
FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------- runtime ----------
FROM python:3.11-slim
LABEL maintainer="hawk-radar"

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

COPY --from=builder /install /usr/local
WORKDIR /app
COPY . .

RUN mkdir -p /data/backups && chown -R appuser:appuser /app /data && chmod +x /app/scripts/docker-entrypoint.sh

EXPOSE 3001

ENV FLASK_ENV=production

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]

CMD ["gunicorn", "wsgi:app", \
     "--bind", "0.0.0.0:3001", \
     "--workers", "1", \
     "--timeout", "120", \
     "--access-logfile", "-"]
