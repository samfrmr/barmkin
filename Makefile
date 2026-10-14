.PHONY: build test install clean validate monitor-demo claude-gate-demo claude-lock-lab shim-test

build:
	go build -o barmkin .

test:
	go test ./... -v

install: build
	sudo ./install.sh

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
