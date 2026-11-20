FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

COPY . /app/

RUN chmod +x /app/entrypoint.sh && \
    addgroup --system pingly && \
    adduser --system --ingroup pingly pingly && \
    mkdir -p /app/staticfiles && \
    chown -R pingly:pingly /app

USER pingly

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health/ || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
