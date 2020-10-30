all: build
build:
	go build -o ./bin/parse ./cmd/parse/parse.go 
	go build -o ./bin/count ./cmd/count/count.go 
	go build -o ./bin/timeseries ./cmd/timeseries/timeseries.go 
clean:
	rm -f ./bin/parse
	rm -f ./bin/count
	rm -f ./bin/timeseries
