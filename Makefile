make:
	go build -o client cmd/ssh_client/main.go
	go build -o server cmd/ssh_server/main.go

clean:
	rm -f client server

all: 
	make clean
	make