# privileged-token-stream-redactor
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
COPY src ./src
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m compileall -q src

FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=builder /build/src ./src
COPY --from=builder /build/requirements.txt ./requirements.txt
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
USER 10001
ENTRYPOINT ["python", "src/main.py"]
