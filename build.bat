set CGO_ENABLED=1
set GOARCH=amd64
go build -ldflags "-H=windowsgui -s -w -extldflags=-static" -trimpath -o block-ads.exe