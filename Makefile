VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO ?= go

.PHONY: all build client server test race vet tidy clean release-local

all: build

build: client server

client:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/goose-client ./cmd/client

server:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/goose-server ./cmd/server

test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin dist

# Local cross-compile dry run, mirroring the GitHub release matrix.
release-local:
	@for entry in linux/amd64 linux/arm64 linux/armv7 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 android/arm64; do \
	  os=$${entry%%/*}; rest=$${entry#*/}; \
	  arch=$${rest%%v*}; arm=$$(echo $$rest | grep -oP '(?<=v)\d' || true); \
	  plat=$$os-$$arch$$([ -n "$$arm" ] && echo "v$$arm" || true); \
	  ext=$$([ "$$os" = "windows" ] && echo ".exe" || echo ""); \
	  echo "==> $$plat"; \
	  client_name=GooseRelayVPN-client-$(VERSION)-$$plat; \
	  server_name=GooseRelayVPN-server-$(VERSION)-$$plat; \
	  mkdir -p dist/$$client_name dist/$$server_name; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$$arm $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$client_name/goose-client$$ext ./cmd/client; \
	  cp client_config.example.json dist/$$client_name/; \
	  if [ "$$os" != "android" ]; then \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOARM=$$arm $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$server_name/goose-server$$ext ./cmd/server; \
	    cp server_config.example.json dist/$$server_name/; \
	  fi; \
	done
	@echo "==> done. binaries in dist/"
