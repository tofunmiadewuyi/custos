.PHONY: build-daemon run-daemon build-api serve-api gen-keys migrate create-admin \
	build-copy-daemon copy-dmon snapshot-daemon snapshot-api \
	release-daemon release-api rerelease-daemon rerelease-api

VERSION ?= dev
GOARCH  ?= amd64
LDFLAGS  = -s -w -X main.version=$(VERSION)

build-daemon:
	go build -o bin/daemon ./cmd/daemon

build-api:
	go build -o bin/api ./cmd/api

run-daemon:
	go build -o bin/daemon ./cmd/daemon && ./bin/daemon

gen-keys:
	go build -o bin/api ./cmd/api && ./bin/api gen-keys

serve-api:
	go build -o bin/api ./cmd/api && ./bin/api serve

migrate:
	go build -o bin/api ./cmd/api && ./bin/api migrate

create-admin:
	go build -o bin/api ./cmd/api && ./bin/api create-admin --email admin@custos.com 

# Releasing = push a prefixed tag; the matching .github/workflows/ job builds + publishes.
# Auto-bumps the patch of the newest tag for that component; override with VERSION=v1.2.3.

# $(1) = component (custosd|api). Cuts and pushes the next tag.
define cut_release
	@comp="$(1)"; \
	if [ "$(VERSION)" != "dev" ]; then next="$$comp/$(VERSION)"; \
	else \
		latest=$$(git tag --sort=-version:refname --list "$$comp/v*" | head -1); \
		if [ -z "$$latest" ]; then next="$$comp/v0.1.0"; \
		else \
			patch=$$(echo "$$latest" | cut -d. -f3); \
			prefix=$$(echo "$$latest" | cut -d. -f1-2); \
			next="$$prefix.$$((patch + 1))"; \
		fi; \
	fi; \
	echo "Tagging $$next"; \
	git tag "$$next" && git push origin "$$next"
endef

# $(1) = component. Deletes + re-pushes the newest tag to re-run its workflow.
define recut_release
	@comp="$(1)"; \
	latest=$$(git tag --sort=-version:refname --list "$$comp/v*" | head -1); \
	if [ -z "$$latest" ]; then echo "no $$comp tag to re-cut"; exit 1; fi; \
	echo "Re-cutting $$latest"; \
	git tag -d "$$latest"; \
	git push origin ":refs/tags/$$latest"; \
	git tag "$$latest" && git push origin "$$latest"
endef

release-daemon:
	$(call cut_release,custosd)

# to override on major updates: make release-api VERSION=v2.0.0
release-api:
	$(call cut_release,api)

rerelease-daemon:
	$(call recut_release,custosd)

rerelease-api:
	$(call recut_release,api)

# Local artifact builds, identical to what CI uploads (test before cutting a tag):
# make snapshot-daemon VERSION=v1.2.3 GOARCH=arm64
snapshot-daemon:
	@mkdir -p dist
	GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags="$(LDFLAGS)" -o dist/custosd ./cmd/daemon
	tar -czf dist/custosd_$(VERSION)_linux_$(GOARCH).tar.gz -C dist custosd && rm dist/custosd

snapshot-api:
	@mkdir -p dist
	GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags="$(LDFLAGS)" -o dist/custos ./cmd/api
	tar -czf dist/custos_$(VERSION)_linux_$(GOARCH).tar.gz -C dist custos && rm dist/custos

build-copy-daemon:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/custosd ./cmd/daemon

copy-dmon:build-copy-daemon
	rsync -avzP -e "ssh -i ~/.ssh/sevena-local" ./bin/custosd sevena@164.92.135.52:/home/sevena/bin


