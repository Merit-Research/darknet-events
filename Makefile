all: build
build:
	go1.14.2 build -o ./bin/parse ./cmd/parse/parse.go 
	go1.14.2 build -o ./bin/count ./cmd/count/count.go 
	go1.14.2 build -o ./bin/timeseries ./cmd/timeseries/timeseries.go 
clean:
	rm -f ./bin/parse
	rm -f ./bin/count
	rm -f ./bin/timeseries
