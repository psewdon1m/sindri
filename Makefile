APP := sindri
VERSION ?= 1.2.0
BUILD_ID ?= local
GO ?= go
DIST := dist
BIN := bin

.PHONY: all build test clean deb fmt

all: build

build:
	mkdir -p $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
		-ldflags "-s -w -X main.version=$(VERSION) -X main.buildID=$(BUILD_ID)" \
		-o $(BIN)/$(APP) ./cmd/sindri

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf $(BIN) $(DIST) .build

deb: build
	rm -rf $(DIST)/debroot
	mkdir -p $(DIST)/debroot/DEBIAN
	mkdir -p $(DIST)/debroot/usr/bin
	mkdir -p $(DIST)/debroot/etc/sindri
	mkdir -p $(DIST)/debroot/var/lib/sindri/backups
	mkdir -p $(DIST)/debroot/var/lib/sindri/recovery
	mkdir -p $(DIST)/debroot/var/lib/sindri/approvals
	mkdir -p $(DIST)/debroot/var/log/sindri/runs
	mkdir -p $(DIST)/debroot/usr/lib/sindri
	mkdir -p $(DIST)/debroot/usr/share/doc/sindri/examples
	cp $(BIN)/$(APP) $(DIST)/debroot/usr/bin/$(APP)
	sed 's/^Version:.*/Version: $(VERSION)/' packaging/debian/control > $(DIST)/debroot/DEBIAN/control
	cp packaging/debian/postinst $(DIST)/debroot/DEBIAN/postinst
	cp install.sh $(DIST)/debroot/usr/lib/sindri/install.sh
	cp docs/nginx.md $(DIST)/debroot/usr/share/doc/sindri/nginx.md
	cp docs/examples/exocortex.conf $(DIST)/debroot/usr/share/doc/sindri/examples/exocortex.conf
	chmod 0644 $(DIST)/debroot/usr/share/doc/sindri/nginx.md
	chmod 0644 $(DIST)/debroot/usr/share/doc/sindri/examples/exocortex.conf
	chmod 0755 $(DIST)/debroot/usr/lib/sindri/install.sh
	chmod 0755 $(DIST)/debroot/DEBIAN/postinst
	dpkg-deb --build $(DIST)/debroot $(DIST)/sindri_$(VERSION)_amd64.deb
