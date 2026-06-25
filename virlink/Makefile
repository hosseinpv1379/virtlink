BINARY   := virlink
CMD      := ./cmd/virlink
GOFLAGS  := -ldflags="-s -w"
LINUX_ENV := GOOS=linux GOARCH=amd64 CGO_ENABLED=0

.PHONY: all build linux tidy clean

all: linux

# Build for current platform (development)
build:
	go build $(GOFLAGS) -o $(BINARY) $(CMD)

# Build a static Linux AMD64 binary (deploy to server)
linux:
	$(LINUX_ENV) go build $(GOFLAGS) -o $(BINARY) $(CMD)
	@echo ""
	@echo "  ✓  built: ./$(BINARY)  ($$(du -sh $(BINARY) | cut -f1))"
	@echo "  upload : scp $(BINARY) root@SERVER:/root/"
	@echo "  run    : sudo ./$(BINARY) -c config.toml"

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
