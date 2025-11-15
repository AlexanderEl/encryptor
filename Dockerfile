# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/encryptor \
    ./cmd/encryptor

# Run tests
RUN go test -race ./...

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 encryptor && \
    adduser -D -u 1000 -G encryptor encryptor

# Set working directory
WORKDIR /home/encryptor

# Copy binary from builder
COPY --from=builder /app/encryptor /usr/local/bin/encryptor

# Change ownership
RUN chown -R encryptor:encryptor /home/encryptor

# Switch to non-root user
USER encryptor

# Create volume for key storage
VOLUME ["/home/encryptor/keys"]

# Default command
ENTRYPOINT ["encryptor"]
CMD ["-version"]

# Metadata
LABEL maintainer="your-email@example.com"
LABEL description="Encryptor - A lightweight service for encrypting/decrypting data"
LABEL version="1.1.0"