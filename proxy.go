package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type requestInf struct {
	Method string              `json:"method"`
	URL    string              `json:"url"`
	Header map[string][]string `json:"header"`
}

type responseInf struct {
	Status string              `json:"status"`
	Header map[string][]string `json:"header"`
}

var mutex = &sync.Mutex{}
var reqPool = make([]*requestInf, 0)
var modifyReqPool = make([]*string, 0)
var respPool = make([]*responseInf, 0)

// curl -x http://127.0.0.1:8080 http://mail.ru
//
//	curl -X POST \
//	 -x http://127.0.0.1:8080 \
//	 http://mail.ru \
//	 -d 'key1=value1&key2=value2'
func main() {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		startProxy()
	}()
	go func() {
		defer wg.Done()
		startAPI()
	}()

	wg.Wait()
}

func startProxy() {
	log.Println("Старт proxy на порту 8080")
	router := mux.NewRouter()
	router.PathPrefix("/").HandlerFunc(handler)

	err := http.ListenAndServe(":8080", router)
	if err != nil {
		log.Fatal("Ошибка при запуске сервера:", err)
	}

}

func startAPI() {
	log.Println("Старт АПИ на порту 8000")
	routerAPI := mux.NewRouter()
	routerAPI.PathPrefix("/requests").HandlerFunc(handleRequests)
	err := http.ListenAndServe(":8000", routerAPI)
	if err != nil {
		log.Fatal("Ошибка при запуске сервера:", err)
	}
}

func handleRequests(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, "Изначальные запросы")
	json.NewEncoder(w).Encode(reqPool)
	fmt.Fprintln(w, "Проксированные запросы")
	json.NewEncoder(w).Encode(modifyReqPool)
	fmt.Fprintln(w, "Перенаправленные ответы от сервера")
	json.NewEncoder(w).Encode(respPool)
}

func handler(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	reqInfo := &requestInf{
		Method: r.Method,
		URL:    r.URL.String(),
		Header: r.Header,
	}

	reqPool = append(reqPool, reqInfo)

	targetURL, err := url.Parse(r.URL.String())
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	port := ""
	if strings.Index(targetURL.Host, ":") == -1 {
		port = ":80"
	}

	conn, err := net.Dial("tcp", targetURL.Host+port)
	if err != nil {
		log.Fatal(err)
	}

	request := r.Method + " / HTTP/1.1\r\n" +
		"Host: " + targetURL.Host + "\r\n"

	for header, values := range r.Header {
		if header != "Proxy-Connection" && header != "Host" {
			for _, value := range values {
				request += header + ": " + value + "\r\n"
			}
		}
	}
	request += "\r\n"

	modifyReqPool = append(modifyReqPool, &request)

	_, err = conn.Write([]byte(request))

	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, r)
	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
	conn.Close()
	respInfo := &responseInf{
		Status: response.Status,
		Header: make(map[string][]string),
	}

	for header, values := range response.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
		respInfo.Header[header] = values
	}

	respPool = append(respPool, respInfo)

	response.Body.Close()
}
