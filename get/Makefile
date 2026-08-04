.PHONY: build clean install

BINARY ?= ./get-credential-linux-amd64

build:
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY)

install: build
	@echo "Built: $(BINARY)"
