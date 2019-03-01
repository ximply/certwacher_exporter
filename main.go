package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	Name           = "cert_exporter"
	listenAddress  = flag.String("unix-sock", "/dev/shm/cert_exporter.sock", "Address to listen on for unix sock access and telemetry.")
	metricsPath    = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	website        = flag.String("web.site", "", "Destination https website(www.xxx.com:443,www.yyy.com:443).")
)

type WebSite struct {
	Host string
	Port string
}

type Remain struct {
	Ws WebSite
	Secs float64
	Err error
}

var gWebSites map[string]WebSite

func check(ws WebSite, wg *sync.WaitGroup, ch *chan Remain) {
	r := Remain{}
	r.Ws.Host = ws.Host
	r.Ws.Port = ws.Port

	sec, err := checkImpl(r.Ws.Host, r.Ws.Port)
	if err != nil {
		r.Err = err
		*ch <- r
		wg.Done()
		return
	}

	r.Secs = float64(sec)
	r.Err = nil
	*ch <- r
	wg.Done()
}

func checkImpl(host, port string) (int, error) {
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
	wg := sync.WaitGroup{}
	ch := make(chan Remain, len(gWebSites))
	for _, v := range gWebSites {
		wg.Add(1)
		go check(v, &wg, &ch)
	}
	wg.Wait()
	close(ch)

	ret := ""

	for i := range ch {
		if i.Err == nil {
			ret += fmt.Sprintf("https_cert_remaining_seconds{domain=\"%s\",port=\"%s\"} %g\n",
				i.Ws.Host, i.Ws.Port, i.Secs)
		}
	}
	ret = strings.TrimRight(ret, "\n")
	io.WriteString(w, ret)
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

	l := strings.Split(*website, ",")
	gWebSites = make(map[string]WebSite)
	for _, v := range l {
		s := strings.Split(v, ":")
		if len(s) != 2 {
			continue
		}

		gWebSites[v] = WebSite{
			Host:s[0],
			Port:s[1],
		}
	}

	if len(gWebSites) < 1 {
		panic("no websites")
	}

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