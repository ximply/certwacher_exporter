package main

import (
	"flag"
	"net"
	"os"
	"net/http"
	"strings"
	"io"
	"time"
	"fmt"
	"crypto/tls"
)

var (
	Name           = "cert_exporter"
	listenAddress  = flag.String("unix-sock", "/dev/shm/cert_exporter.sock", "Address to listen on for unix sock access and telemetry.")
	metricsPath    = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	website        = flag.String("web.site", "", "Destination https website(www.xxx.com:443).")
)

var g_host string
var g_port string

func check(host, port string) (int, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host + ":" + port, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer conn.Close()

	if err != nil {
		return -1, err
	}

	if err := conn.Handshake(); err != nil {
		return -1, err
	}

	for _, cert := range conn.ConnectionState().PeerCertificates {
		if cert.IsCA {
			continue
		}

		now := time.Now()

		left := time.Until(cert.NotAfter) - time.Until(now)
		return int(left.Seconds()), nil

	}

	return -1, nil
}

func metrics(w http.ResponseWriter, r *http.Request) {
	sec, err := check(g_host, g_port)
	if err == nil {
		io.WriteString(w,
			fmt.Sprintf("https_cert_remaining_seconds{domain=\"%s\",port=\"%s\"} %g",
				g_host, g_port, float64(sec)))
	} else {
		io.WriteString(w, "")
	}

}

func main() {
	flag.Parse()

	addr := "/dev/shm/cert_exporter.sock"
	if listenAddress != nil {
		addr = *listenAddress
	}

	if website == nil {
		panic("no website")
	}

	l := strings.Split(*website, ":")
	if len(l) != 2 {
		panic("error website")
	}
	g_host = l[0]
	g_port = l[1]

	mux := http.NewServeMux()
	mux.HandleFunc(*metricsPath, metrics)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Https Cert Exporter</title></head>
             <body>
             <h1>Https Cert Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	server := http.Server{
		Handler: mux, // http.DefaultServeMux,
	}
	os.Remove(addr)

	listener, err := net.Listen("unix", addr)
	if err != nil {
		panic(err)
	}
	server.Serve(listener)
}