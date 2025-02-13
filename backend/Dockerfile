FROM rust:1.84.1 AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y musl-tools pkg-config libssl-dev
RUN rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/todos_backend /app/main
EXPOSE 8080
CMD ["/app/main"]
