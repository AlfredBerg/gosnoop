GO      ?= go
BINARY  ?= gosnoop
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# CGO_ENABLED=0 keeps the binary static, so it can be copied to a machine that
# does not have the same libc.
export CGO_ENABLED = 0

LDFLAGS := -X main.version=$(VERSION)

.PHONY: all
all: build

## generate: compile the eBPF C programs and regenerate their Go bindings
.PHONY: generate
generate: check-clang
	$(GO) generate ./...

## build: build the gosnoop binary for the host architecture
.PHONY: build
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## build-all: cross-build for every architecture the probes support
.PHONY: build-all
build-all:
	GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64 .
	GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64 .

## test: run the unit tests
.PHONY: test
test:
	$(GO) test ./...

## vet: run go vet and check formatting
.PHONY: vet
vet:
	$(GO) vet ./...
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

## run: build and trace, needs root
.PHONY: run
run: build
	sudo ./$(BINARY) $(ARGS)

## clean: remove build output
.PHONY: clean
clean:
	rm -f $(BINARY) $(BINARY)-linux-*

# bpf2go shells out to clang, and a missing one produces a confusing error
# deep inside go generate.
.PHONY: check-clang
check-clang:
	@command -v $${BPF2GO_CC:-clang} >/dev/null || { \
		echo "clang not found. Install clang and the libbpf headers; see the README."; exit 1; }

## help: list the targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
