start:
	docker build -t go-proxy-server .
	docker run -p 8080:8080 -p 8000:8000 go-proxy-server