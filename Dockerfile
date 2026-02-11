# Medic Agent - Dockerfile

FROM python:3.11-slim as builder

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim

RUN groupadd -r medic && useradd -r -g medic medic
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=medic:medic . .

RUN mkdir -p /app/data /app/logs && \
    chown -R medic:medic /app/data /app/logs

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MEDIC_CONFIG_PATH=/app/config/medic.yaml \
    MEDIC_MODE=observer

EXPOSE 8000
USER medic
ENTRYPOINT ["python", "main.py"]
