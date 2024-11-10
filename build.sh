#!/bin/bash
echo "=== Tidy and Update ==="
go mod tidy
go get -u ./...
echo "=== Building ==="
go build -o ./bin/logwisp ./src/cmd/main.go
echo "=== Testing ==="
go test ./...
echo "=== Done ==="
