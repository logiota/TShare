BIN := tshare
PREFIX ?= /usr/local

build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) .

install: build
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

cross:
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/$(BIN)-darwin-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/$(BIN)-darwin-amd64 .
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/$(BIN)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/$(BIN)-linux-arm64 .

clean:
	rm -rf $(BIN) dist

.PHONY: build install cross clean
