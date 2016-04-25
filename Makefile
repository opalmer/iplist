all: deps build.linux build.freebsd build.darwin

build.%:
	GOOS=$* GOARCH=amd64 go build -o build/iplists.$*-amd64 iplists.go

deps:
	go get github.com/Sirupsen/logrus
	go get github.com/opalmer/awsips
	go get github.com/domainr/whois