FROM rust:1.84.1 AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y \
    musl-tools \
    pkg-config \
    libssl-dev \
    libssl-dev:amd64 \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

# Set environment variable for OpenSSL
ENV OPENSSL_DIR="/usr"
ENV OPENSSL_LIB_DIR="/usr/lib/x86_64-linux-gnu"
ENV OPENSSL_INCLUDE_DIR="/usr/include"

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {println!(\"Placeholder\");}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
# RUN rm src/main.rs
RUN touch src/lib.rs
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/todos_backend /app/main
EXPOSE 8080
CMD ["/app/main"]
