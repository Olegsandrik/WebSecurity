package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var counter = big.NewInt(10000000000)

type ProxyServer struct {
	Addr      string
	tlsConfig *tls.Config
}

func NewProxyServer(addr string) *ProxyServer {
	return &ProxyServer{Addr: addr}
}

func (p *ProxyServer) Start() {
	httpServer := &http.Server{
		Addr:    p.Addr,
		Handler: http.HandlerFunc(p.handleConnect),
	}

	log.Println("Старт прокси на", p.Addr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		p.handleHTTPSConn(w, r)
	} else {
		fmt.Println("Поддержка только CONNECT-соединений")
	}
}

func (p *ProxyServer) handleHTTPSConn(w http.ResponseWriter, r *http.Request) {
	hostWithPort := r.Host
	host := strings.Split(hostWithPort, ":")[0]

	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Не удалось получить управление сокетом", http.StatusInternalServerError)
		return
	}

	connClient, _, err := hij.Hijack()
	if err != nil {
		http.Error(w, "Ошибка  hijack-соедиения", http.StatusServiceUnavailable)
		return
	}
	defer connClient.Close()

	_, err = connClient.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Println("Ошибка отправки удачного соединения:", err)
		return
	}

	connServ, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Println("Ошибка соединения с хостом:", err)
		return
	}
	defer connServ.Close()

	certPair, err := p.genCertificate(host)
	if err != nil {
		log.Print("Ошибка загрузки сертификата ", err)
		return
	}
	log.Print("Успешная загрузка сертификата")

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{certPair},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	tlsConnClient := tls.Server(connClient, tlsConf)
	err = tlsConnClient.Handshake()
	if err != nil {
		log.Println("TLS рукопожатие с клиентом не получилось:", err)
		return
	}
	defer tlsConnClient.Close()

	tlsConnServ := tls.Client(connServ, &tls.Config{InsecureSkipVerify: true})
	err = tlsConnServ.Handshake()
	if err != nil {
		log.Println("TLS рукопожатие с сервером не получилось:", err)
		return
	}
	defer tlsConnServ.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(tlsConnServ, tlsConnClient)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(tlsConnClient, tlsConnServ)
	}()

	wg.Wait()

	tlsConnClient.Close()
	tlsConnServ.Close()
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

func main() {
	proxy := NewProxyServer(":8080")
	proxy.Start()
}
