FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
COPY --from=builder /install /usr/local
USER 10001
ENTRYPOINT ["python", "-m", "privileged_token_stream_redactor"]
