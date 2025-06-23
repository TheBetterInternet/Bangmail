.PHONY: build clean server client
build: server client
server:
	go build -o bin/bangmaild cmd/server/main.go

client:
	go build -o bin/bangmail cmd/client/main.go

clean:
	rm -rf bin/

install: build
	sudo cp bin/bangmaild /usr/local/bin/
	sudo cp bin/bangmail /usr/local/bin/

test:
	go test ./...

.DEFAULT_GOAL := build
