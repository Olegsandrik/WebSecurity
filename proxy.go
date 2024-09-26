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

	w.WriteHeader(http.StatusOK)

	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Не удалось получить управление сокетом", http.StatusInternalServerError)
		return
	}

	conn, _, err := hij.Hijack()
	if err != nil {
		log.Println("Ошибка при захвате соединения:", err)
		return
	}

	p.genCertificate(host)

	connServ, err := net.Dial("tcp", hostWithPort)
	if err != nil {
		log.Fatal("Не удалось установить TLS-соединение с сервером")
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(connServ, conn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, connServ)
	}()

	wg.Wait()

	conn.Close()
	connServ.Close()
}

func (p *ProxyServer) genCertificate(host string) (tls.Certificate, error) {
	commonName := host
	counter++
	serialNumber := strconv.Itoa(counter)

	cmd := exec.Command("./gen_cert.sh", commonName, serialNumber)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command execution failed: %s\nOutput: %s\n", err, output)
		return tls.Certificate{}, fmt.Errorf("failed to generate certificate: %w", err)
	}
	log.Printf("Certificate generation output: %s\n", output)

	cert, err := ioutil.ReadFile("cert.crt")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert.crt: %w", err)
	}

	key, err := ioutil.ReadFile("cert.key")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert.key: %w", err)
	}

	certPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate pair: %w", err)
	}

	// log.Println("Successfully generated certificate for:", commonName)
	return certPair, nil
}

func main() {
	proxy := NewProxyServer(":8080")
	proxy.Start()
}
