ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: build test test-docker bench coverage coverage-html reportcard generated

build:
	go build -o gojose ./cmd/gojose

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -bench=. -benchmem ./...

coverage:
	go test -coverpkg=./internal/...,./pkg/... -coverprofile=coverage.out ./internal/... ./pkg/...
	go tool cover -func coverage.out

coverage-html: coverage
	go tool cover -html=coverage.out

reportcard:
	goreportcard-cli -v

generated:
	go generate ./pkg/...