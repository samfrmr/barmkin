.PHONY: build test install clean validate monitor-demo claude-gate-demo shim-test

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

shim-test:
	cd plugins/claude-code/barmkin-shim && node --test shim.test.ts

clean:
	rm -f barmkin
