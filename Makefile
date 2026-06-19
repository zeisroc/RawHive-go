APP     := rawhive
GO      := go
GOFLAGS := -trimpath -mod=readonly
LDFLAGS := -s -w

VERSION  ?=
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

LDFLAGS += -X 'main.gitCommit=$(GIT_COMMIT)'
LDFLAGS += -X 'main.buildTime=$(BUILD_TIME)'
ifneq ($(VERSION),)
LDFLAGS += -X 'main.version=$(VERSION)'
endif

.PHONY: all clean build

all: build

build:
	@mkdir -p dist
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(APP)-amd64.exe
	GOOS=windows GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/$(APP)-arm64.exe

clean:
	rm -rf dist
