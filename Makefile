.PHONY: build run test clean docker-build docker-run

# Build the application
build:
	go build -o bin/securityai ./cmd/main.go

# Run the application
run:
	go run ./cmd/main.go

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Build docker image
docker-build:
	docker build -t securityai .

# Run docker compose
docker-run:
	docker-compose up -d

# Stop docker compose
docker-stop:
	docker-compose down

# Show logs
logs:
	docker-compose logs -f

# Run linter
lint:
	golangci-lint run

# Generate mock files for testing
mocks:
	mockgen -destination=internal/mocks/repository_mocks.go -package=mocks github.com/jinye/securityai/internal/domain/repository EventRepository,VectorRepository,CacheRepository

# Initialize development environment
init:
	go mod download
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/golang/mock/mockgen@latest
