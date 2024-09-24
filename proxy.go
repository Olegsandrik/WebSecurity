package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

func main() {
	startProxy()
}

func startProxy() {
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(handleConnect),
	}

	log.Println("Старт proxy на порту 8080")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
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

	exec.Command("bash", "./gen_cert.sh", host)

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
