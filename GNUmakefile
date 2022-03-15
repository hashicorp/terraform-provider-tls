GOLANGCILINT_INSTALLED := $(shell command -v golangci-lint 2> /dev/null)

default: build

build:
	go build -v ./...

lint:
ifndef GOLANGCILINT_INSTALLED
	$(error "Please install 'golangci-lint' (https://golangci-lint.run/)")
endif
	golangci-lint run

generate:
	go generate ./...

fmt:
	go fmt -x ./...

test:
	go test -v -cover -timeout=120s -parallel=4 ./...

testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

.PHONY: build lint generate fmt test testacc
