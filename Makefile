.PHONY: build test vet install run clean

BIN=bin/caa-lint

build:
	go build -o $(BIN) ./cmd/caa-lint

test:
	go test -race ./...

vet:
	go vet ./...

install:
	go install ./cmd/caa-lint

run: build
	$(BIN) --domain example.com

clean:
	rm -rf bin
