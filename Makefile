.PHONY: build test install clean validate monitor-demo

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

clean:
	rm -f barmkin
