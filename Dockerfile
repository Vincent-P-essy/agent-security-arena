FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --prefix=/install .

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 arena
WORKDIR /app
COPY --from=builder /install /usr/local
COPY scenarios ./scenarios
COPY web ./web
USER 10001
EXPOSE 8080
ENTRYPOINT ["agent-arena"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]

