# Build stage
FROM python:3.12-slim-bookworm AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY CMakeLists.txt ./
COPY src ./src

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --parallel

# Runtime stage
FROM python:3.12-slim-bookworm AS runtime

WORKDIR /app

COPY --from=builder /app/build/server ./server

EXPOSE 2053/udp

ENTRYPOINT ["/app/server"]
