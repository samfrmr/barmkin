.PHONY: build test install clean validate monitor-demo claude-gate-demo claude-lock-lab shim-test managed-install managed-uninstall packaging-test-ubuntu packaging-test-nixos

build:
	go build -o barmkin .

test:
	go test ./... -v

install: build
	sudo ./install.sh

# The root-managed monitor and managed Claude Code seat (packaging/).
managed-install:
	CGO_ENABLED=0 go build -o barmkin .
	sudo packaging/install.sh install

managed-uninstall:
	sudo packaging/install.sh uninstall

packaging-test-ubuntu:
	packaging/test/ubuntu.sh

packaging-test-nixos:
	nix-build packaging/nixos/test.nix

validate: build
	./barmkin validate

monitor-demo:
	./scripts/monitor-demo.sh

claude-gate-demo:
	./scripts/claude-gate-demo.sh

claude-lock-lab:
	./scripts/claude-lock-lab.sh

shim-test:
	cd plugins/claude-code && claude plugin validate --strict barmkin-shim && claude plugin test barmkin-shim

clean:
	rm -f barmkin
