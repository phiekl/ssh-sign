# SPDX-FileCopyrightText: 2026 Philip Eklöf
#
# SPDX-License-Identifier: MIT

BUILD_DIR := build
BINARY := $(BUILD_DIR)/ssh-sign
SBOM := $(BINARY).spdx.json
MANPAGES := $(BUILD_DIR)/man/ssh-sign.1 $(BUILD_DIR)/man/ssh-sign-allowed-signers.5
MAN_SCRIPTS := doc/scripts/md2man.sed doc/scripts/man.sed Makefile
# A man page's date: MAN_DATE if set, or its source's last commit date.
man_date = $(or $(MAN_DATE),$(shell git log -1 --format=%cs -- $(1) 2>/dev/null))
GOAMD64 ?= v3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
MD2MAN ?= go-md2man
SYFT ?= syft
TAGS ?=
GOTAGS := $(if $(TAGS),-tags $(TAGS))

.PHONY: all build man sbom test fuzz vet clean

all: test vet build

# Pass the version through the environment, so the shell does not parse it.
build: export SSH_SIGN_VERSION = $(VERSION)
build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOAMD64=$(GOAMD64) go build $(GOTAGS) -trimpath -ldflags="-s -w -X pxy.se/go/ssh-sign/internal/cmd.version=$$SSH_SIGN_VERSION" -o $(BINARY) .

man: $(MANPAGES)

# man_page renders Markdown $(1) as man page $(2) of section $(3),
# with volume title $(4).
define man_page
	mkdir -p $(@D)
	{ printf '%s\n==\n\n# NAME\n\n%s - ' '$(2) $(3) "$(call man_date,$(1))" ssh-sign "$(4)"' '$(2)'; \
		sed -E -f doc/scripts/md2man.sed $(1); } > $@.md
	$(MD2MAN) -in $@.md -out $@
	rm $@.md
	sed -E -i -f doc/scripts/man.sed $@
endef

$(BUILD_DIR)/man/ssh-sign.1: doc/ssh-sign.1.md $(MAN_SCRIPTS)
	$(call man_page,$<,ssh-sign,1,User Commands)

$(BUILD_DIR)/man/ssh-sign-allowed-signers.5: doc/ssh-sign-allowed-signers.5.md $(MAN_SCRIPTS)
	$(call man_page,$<,ssh-sign-allowed-signers,5,File Formats)

sbom: build
	$(SYFT) scan file:$(BINARY) --output spdx-json=$(SBOM)

test:
	go test $(GOTAGS) ./...

FUZZTIME ?= 10s
fuzz:
	go test ./pkg/sshsig -run '^$$' -fuzz '^FuzzSignatureRead$$' -fuzztime=$(FUZZTIME) -parallel=2
	go test ./pkg/allowedsigners -run '^$$' -fuzz '^FuzzParse$$' -fuzztime=$(FUZZTIME) -parallel=2
	go test ./pkg/allowedsigners -run '^$$' -fuzz '^FuzzWildcardMatch$$' -fuzztime=$(FUZZTIME) -parallel=2

vet:
	go vet $(GOTAGS) ./...

clean:
	rm -rf $(BUILD_DIR)
