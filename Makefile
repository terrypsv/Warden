BINARY := warden
VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: fmt vet test build check clean

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./... -count=1

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/warden

check: fmt vet test build

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist
