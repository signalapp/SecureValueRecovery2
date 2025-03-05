# SVR2 Host Code

This codebase provides a host-side binary for running and interacting with
an enclave, while also interacting with the outside world (external services,
clients, etc), and acts as a bridge between these two worlds.  It follows
typical Go paradigms.

## Go Version

This code was developed on Go 1.19+, so yay, generics are a thing.

## Testing

The usual `go test ./...` won’t necessarily work, because some tests depend on the enclave
and generated code. Run `make -C .. [docker_]host_test`

## Formatting

One `gofmt` to rule them all, except `goimports` for, you know, the imports:
```shell
go install golang.org/x/tools/cmd/goimports@latest # if needed
goimports -w -local 'github.com/signalapp/svr2' $(find . -name '*.go' -not -path '*.pb.go')
```
