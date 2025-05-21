FROM golang:1.20-alpine AS builder

WORKDIR /app

# Install git and build dependencies
RUN apk add --no-cache git build-base

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o securityai ./cmd/main.go

# Use a minimal alpine image
FROM alpine:3.14

WORKDIR /app

# Install CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy the binary from builder
COPY --from=builder /app/securityai .
COPY --from=builder /app/config /app/config

# Expose the application port
EXPOSE 8080

# Run the binary
CMD ["./securityai"]
