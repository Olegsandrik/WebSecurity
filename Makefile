start:
	docker build -t mongodb .
	docker run -p 27017:27017 mongodb