FROM golang:latest 
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download
RUN go build -o main .
EXPOSE 8080 8000
CMD ["/app/main"]