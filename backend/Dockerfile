FROM golang:1.23.4 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /app/main ./main.go

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["sh", "-c", "echo DATABASE_URL=$DATABASE_URL && ./main"]
