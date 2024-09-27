package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

var counter = 20

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

	log.Println("Starting proxy on port", p.Addr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		p.handleHTTPSConn(w, r)
	} else {
		fmt.Println("Only support CONNECT")
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
		http.Error(w, "Error hijacking connection", http.StatusServiceUnavailable)
		return
	}
	defer connClient.Close()

	_, err = connClient.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Println("Failed to send connection established:", err)
		return
	}

	connServ, err := net.Dial("tcp", r.Host)
	if err != nil {
		log.Println("Failed to connect to destination:", err)
		return
	}
	defer connServ.Close()

	certPair, err := p.genCertificate(host)
	if err != nil {
		log.Print("Failed to load certificate ", err)
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

func (p *ProxyServer) genCertificate(host string) (tls.Certificate, error) {
	commonName := host
	counter++
	serialNumber := strconv.Itoa(counter)

	// Генерация сертификата
	cmd := exec.Command("./gen_cert.sh", commonName, serialNumber)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command execution failed: %s\nOutput: %s\n", err, output)
		return tls.Certificate{}, fmt.Errorf("failed to generate certificate: %w", err)
	}

	// Чтение сертификата и ключа
	cert, err := ioutil.ReadFile("certs/" + host + ".crt")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert.crt: %w", err)
	}
	key, err := ioutil.ReadFile("certs/" + host + ".key")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert.key: %w", err)
	}

	/*
		defer os.Remove("certs/" + host + ".crt")
		defer os.Remove("certs/" + host + ".key")
	*/

	certPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate pair: %w", err)
	}

	log.Println("Successfully used certificate for:", commonName)
	return certPair, nil
}

func main() {
	proxy := NewProxyServer(":8080")
	proxy.Start()
}
