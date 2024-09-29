package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/net/context"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var mutex = &sync.Mutex{}

var counter = big.NewInt(10000000000)

type Request struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	GetParams  map[string][]string
	Headers    map[string][]string
	Cookies    []*http.Cookie
	PostParams map[string][]string
}

type Response struct {
	Body    string
	Headers map[string][]string
}

type ProxyServer struct {
	Addr      string
	tlsConfig *tls.Config
	db        *mongo.Database
}

func NewProxyServer(addr string, db *mongo.Database) *ProxyServer {
	return &ProxyServer{Addr: addr, db: db}
}

func (p *ProxyServer) Start() {
	httpServer := &http.Server{
		Addr:    p.Addr,
		Handler: http.HandlerFunc(p.handleConnect),
	}

	log.Println("Starting proxy on", p.Addr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Proxy request:", r.Method, r.URL)
	if r.Method == http.MethodConnect {
		p.handleHTTPSConn(w, r)
	} else if r.Method == http.MethodPost || r.Method == http.MethodHead || r.Method == http.MethodGet || r.Method == http.MethodPut {
		p.handleHTTPConn(w, r)
	} else {
		http.Error(w, "Only CONNECT methods are supported", http.StatusMethodNotAllowed)
	}
}

func (p *ProxyServer) handleHTTPSConn(w http.ResponseWriter, r *http.Request) {
	request := Request{
		Method:     r.Method,
		Path:       r.URL.Path,
		GetParams:  r.URL.Query(),
		Headers:    r.Header,
		Cookies:    r.Cookies(),
		PostParams: r.PostForm,
	}
	fmt.Println("REQUEST: ", request)
	p.saveRequestAndResponse(p.db, request, "request")

	hostWithPort := r.Host
	host := strings.Split(hostWithPort, ":")[0]

	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Unable to hijack socket", http.StatusInternalServerError)
		return
	}

	connClient, _, err := hij.Hijack()
	if err != nil {
		http.Error(w, "Error hijacking connection", http.StatusServiceUnavailable)
		return
	}
	defer connClient.Close()

	_, err = connClient.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Println("Error sending successful connection:", err)
		return
	}

	connServ, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Println("Error connecting to host:", err)
		return
	}
	defer connServ.Close()

	certPair, err := p.genCertificate(host)
	if err != nil {
		log.Print("Error loading certificate ", err)
		return
	}
	log.Print("Successfully loaded certificate")

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	tlsConnClient := tls.Server(connClient, tlsConf)
	err = tlsConnClient.Handshake()
	if err != nil {
		log.Println("TLS handshake with client failed:", err)
		return
	}
	defer tlsConnClient.Close()

	tlsConnServ := tls.Client(connServ, &tls.Config{InsecureSkipVerify: true})
	err = tlsConnServ.Handshake()
	if err != nil {
		log.Println("TLS handshake with server failed:", err)
		return
	}
	defer tlsConnServ.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy data from client to server
	go func() {
		defer wg.Done()
		_, err := io.Copy(tlsConnServ, tlsConnClient)
		if err != nil {
			log.Println("Error copying data from client to server:", err)
		}
	}()

	go func() {
		defer wg.Done()
		var responseBuffer bytes.Buffer
		tee := io.TeeReader(tlsConnServ, &responseBuffer)

		_, err := io.Copy(tlsConnClient, tee)
		if err != nil {
			log.Println("Error copying data from server to client:", err)
		}

		response := Response{
			Headers: make(map[string][]string),
		}

		for key, values := range r.Header {
			response.Headers[key] = values
		}

		contentEncoding := response.Headers["Content-Encoding"]
		if len(contentEncoding) > 0 && contentEncoding[0] == "gzip" {
			reader, err := gzip.NewReader(&responseBuffer)
			if err != nil {
				log.Println("Error creating gzip reader:", err)
				return
			}
			defer reader.Close()

			decodedBody, err := io.ReadAll(reader)
			if err != nil {
				log.Println("Error reading decoded body:", err)
				return
			}
			response.Body = string(decodedBody)
		} else {
			response.Body = responseBuffer.String()
		}

		p.saveRequestAndResponse(p.db, response, "response")
	}()

	wg.Wait()
}

func readFileLineByLine(filename string) ([]byte, error) {
	var content []byte
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		content = append(content, scanner.Bytes()...)
		content = append(content, '\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return content, nil
}

func (p *ProxyServer) handleHTTPConn(w http.ResponseWriter, r *http.Request) {
	request := Request{
		Method:     r.Method,
		Path:       r.URL.Path,
		GetParams:  r.URL.Query(),
		Headers:    r.Header,
		Cookies:    r.Cookies(),
		PostParams: r.PostForm,
	}
	fmt.Println("REQUEST: ", request)
	p.saveRequestAndResponse(p.db, request, "request")

	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		http.Error(w, "Target URL must start with http", http.StatusBadRequest)
		return
	}

	parsedTargetUrl, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	req, err := http.NewRequest(r.Method, parsedTargetUrl.RequestURI(), r.Body)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		log.Println("Error creating request:", err)
		return
	}

	req.Header = r.Header.Clone()
	req.Host = parsedTargetUrl.Host
	req.URL.Scheme = parsedTargetUrl.Scheme
	req.URL.Host = parsedTargetUrl.Host

	req.Header.Del("Proxy-Connection")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error sending request to target server", http.StatusBadGateway)
		log.Println("Error sending request to server:", err)
		return
	}
	defer resp.Body.Close()

	response := Response{
		Headers: make(map[string][]string),
	}

	for key, values := range resp.Header {
		response.Headers[key] = values
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return
	}
	response.Body = string(bodyBytes)

	p.saveRequestAndResponse(p.db, response, "response")

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("Error sending response to client:", err)
	}
}

func (p *ProxyServer) genCertificate(host string) (tls.Certificate, error) {
	commonName := host
	counter.Add(counter, big.NewInt(1))
	serialNumber := counter

	caCertBYTES, err := readFileLineByLine("rootCA.crt")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка чтения корневого сертификата: %v", err)
	}

	caKeyBYTES, err := readFileLineByLine("rootCA.key")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка чтения корневого ключа: %v", err)
	}

	caCertBlock, _ := pem.Decode(caCertBYTES)
	caKeyBlock, _ := pem.Decode(caKeyBYTES)

	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка с корневый сертификатом: %v", err)
	}

	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка с корневым ключом: %v", err)
	}

	hostPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка генерации приватного ключа для хоста: %v", err)
	}

	hostCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	hostCertBytes, err := x509.CreateCertificate(rand.Reader, hostCertTemplate, caCert, &hostPrivateKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка создания сертификата: %v", err)
	}

	hostCertFile, err := os.Create(fmt.Sprintf("certs/%s.crt", host))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка создания файла сертификата: %v", err)
	}
	defer hostCertFile.Close()

	err = pem.Encode(hostCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: hostCertBytes})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка записи сертификата в файл: %v", err)
	}

	hostKeyFile, err := os.Create(fmt.Sprintf("certs/%s.key", host))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка создания ключа: %v", err)
	}
	defer hostKeyFile.Close()

	err = pem.Encode(hostKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(hostPrivateKey)})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ошибка записи в файл: %v", err)
	}

	certFile := fmt.Sprintf("certs/%s.crt", host)
	certKey := fmt.Sprintf("certs/%s.key", host)

	cert, err := tls.LoadX509KeyPair(certFile, certKey)
	if err != nil {
		log.Printf("Ошибка загрузки %s и ключа %s: %v", certFile, certKey, err)
		return tls.Certificate{}, fmt.Errorf("error: %v", err)

	}

	defer os.Remove("certs/" + host + ".crt")
	defer os.Remove("certs/" + host + ".key")
	return cert, nil
}

func (p *ProxyServer) saveRequestAndResponse(db *mongo.Database, item interface{}, itemType string) {
	var collection *mongo.Collection

	switch itemType {
	case "request":
		collection = db.Collection("request")
	case "response":
		collection = db.Collection("response")
	default:
		log.Println("Неизвестный тип элемента:", itemType)
		return
	}

	_, err := collection.InsertOne(context.TODO(), item)
	if err != nil {
		log.Println("Ошибка при добавлении элемента в базу данных:", err)
	} else {
		log.Println("Элемент успешно сохранен в базу данных:")
		log.Println(item)
	}
}

func ConnectToMongoDataBase() *mongo.Database {
	ctx := context.TODO()
	clientOptions := options.Client().ApplyURI("mongodb://Nikitin:HW3@localhost:27017")
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("DataBase connect err:", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("DataBase ping err:", err)
	}
	log.Println("Successful connected to MongoDB")

	database := client.Database("task3")
	return database
}

func main() {
	go startAPI()
	database := ConnectToMongoDataBase()
	proxy := NewProxyServer(":8080", database)
	proxy.Start()

}

func startAPI() {
	log.Println("Старт АПИ на порту 8000")
	routerAPI := mux.NewRouter()
	routerAPI.PathPrefix("/requests").HandlerFunc(handleRequests)
	routerAPI.PathPrefix("/responses").HandlerFunc(handleRequestsResp)
	err := http.ListenAndServe(":8000", routerAPI)
	if err != nil {
		log.Fatal("Ошибка при запуске сервера:", err)
	}
}

func handleRequests(w http.ResponseWriter, r *http.Request) {
	database := ConnectToMongoDataBase()
	collection := database.Collection("request")
	cursor, err := collection.Find(context.TODO(), bson.D{})
	if err != nil {
		http.Error(w, "Ошибка при получении документов из базы данных", http.StatusInternalServerError)
		log.Fatal("Ошибка при получении документов из базы данных:", err)
		return
	}

	defer func() {
		if err := cursor.Close(context.TODO()); err != nil {
			log.Println("Ошибка при закрытии курсора:", err)
		}
	}()

	var documents []bson.M
	if err := cursor.All(context.TODO(), &documents); err != nil {
		http.Error(w, "Ошибка при декодировании документов", http.StatusInternalServerError)
		log.Println("Ошибка при декодировании документов:", err)
		return
	}

	jsonData, err := json.Marshal(documents)
	if err != nil {
		http.Error(w, "Ошибка при кодировании данных в JSON", http.StatusInternalServerError)
		log.Println("Ошибка при кодировании данных в JSON:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

func handleRequestsResp(w http.ResponseWriter, r *http.Request) {
	database := ConnectToMongoDataBase()
	collection := database.Collection("response")
	cursor, err := collection.Find(context.TODO(), bson.D{})
	if err != nil {
		http.Error(w, "Ошибка при получении документов из базы данных", http.StatusInternalServerError)
		log.Fatal("Ошибка при получении документов из базы данных:", err)
		return
	}

	defer func() {
		if err := cursor.Close(context.TODO()); err != nil {
			log.Println("Ошибка при закрытии курсора:", err)
		}
	}()

	var documents []bson.M
	if err := cursor.All(context.TODO(), &documents); err != nil {
		http.Error(w, "Ошибка при декодировании документов", http.StatusInternalServerError)
		log.Println("Ошибка при декодировании документов:", err)
		return
	}

	jsonData, err := json.Marshal(documents)
	if err != nil {
		http.Error(w, "Ошибка при кодировании данных в JSON", http.StatusInternalServerError)
		log.Println("Ошибка при кодировании данных в JSON:", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}
