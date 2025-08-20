NAME=$(basename $(notdir ${CURDIR}))

.PHONY: all linux darwin clean

server:
	AUTH_TOKEN=hello go run main.go server
client:
	AUTH_TOKEN=hello go run main.go client --url ws://127.0.0.1:8080/ws
cmd:
	curl -sd '{"command":"touch a","workdir":"test","timeout":60}' http://127.0.0.1:8080/cmd?token=hello | jq
	curl -sd '{"command":"pwd","workdir":"test","timeout":60}' http://127.0.0.1:8080/cmd?token=hello | jq -r .output
	curl -sd '{"command":"ls -lah","workdir":"test","timeout":60}' http://127.0.0.1:8080/cmd?token=hello | jq -r .output
	curl -sd '{"command":"rm a","workdir":"test","timeout":60}' http://127.0.0.1:8080/cmd?token=hello | jq
	curl -sd '{"command":"rm a","workdir":"test","timeout":60}' http://127.0.0.1:8080/cmd?token=hello | jq
health:
	curl -s http://127.0.0.1:8080/health | jq
proxy:
	curl -s http://127.0.0.1:8080/proxy/8080/health?token=hello | jq
all: linux darwin
	ls -lah ${NAME}*
linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(NAME)_linux .

darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o $(NAME)_darwin .

clean:
	rm -f $(NAME)_*
