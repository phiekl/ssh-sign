# SPDX-FileCopyrightText: 2026 Philip Eklöf
#
# SPDX-License-Identifier: MIT

BUILD_DIR := build
BINARY := $(BUILD_DIR)/ssh-sign
SBOM := $(BINARY).spdx.json
GOAMD64 ?= v3
SYFT ?= syft

.PHONY: all build sbom test vet clean

all: test vet build

# CGO must stay off for the service unit's syscall allowlist.
build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOAMD64=$(GOAMD64) go build -trimpath -ldflags="-s -w" -o $(BINARY) .

sbom: build
	$(SYFT) scan file:$(BINARY) --output spdx-json=$(SBOM)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)
