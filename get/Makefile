.PHONY: build clean install

BINARY = get

build:
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY)

install: build
	@echo "Built: $(BINARY)"
