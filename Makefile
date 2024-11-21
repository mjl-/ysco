build:
	CGO_ENABLED=0 go build
	./genlicenses.sh
	./gendoc.sh
	./gencapmap.sh
	CGO_ENABLED=0 go build
	CGO_ENABLED=0 go vet
	CGO_ENABLED=0 go vet -tags integration

race:
	go build -race

test:
	CGO_ENABLED=0 go test -shuffle=on -coverprofile cover.out
	go tool cover -html=cover.out -o cover.html

test-integration:
	# WARNING: the test uses ysco from the last git commit, not from the working directory. commit changes before testing.
	-docker-compose down
	docker-compose build
	docker-compose run test

run:
	# -updateschedule mo 
	./ysco run -loglevel debug -updatedelay 5s -updatejitter 5s -adminaddr localhost:2200 -metricsaddr localhost:2201 -monitordelay 3s ./moxtools

run-root:
	./ysco run -user 1000 -loglevel debug -updatedelay 5s -updatejitter 5s -adminaddr localhost:2200 -metricsaddr localhost:2201 -monitordelay 3s ./moxtools

check:
	GOARCH=386 CGO_ENABLED=0 go vet
	CGO_ENABLED=0 staticcheck

check-shadow:
	go vet -vettool=$$(which shadow) ./... 2>&1 | grep -v '"err"'

govendor:
	go mod tidy
	go mod vendor

buildall:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=netbsd GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=dragonfly GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=illumos GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=solaris GOARCH=amd64 go build
	CGO_ENABLED=0 GOOS=aix GOARCH=ppc64 go build
	# no sigusr1/2, setpgid, CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build
	# no sigusr1/2, setpgid, CGO_ENABLED=0 GOOS=plan9 GOARCH=amd64 go build

fmt:
	go fmt ./...
	gofmt -w -s *.go

clean:
	CGO_ENABLED=0 go clean
