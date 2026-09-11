set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64
go build -o wardennet_linux -trimpath -ldflags="-s -w -X main.Version=v0.2" ./cmd/wardennet
