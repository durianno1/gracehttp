package gracehttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// 当前OCSP查询内存缓存
var cache []byte
var locker sync.RWMutex

const (
	GRACEFUL_ENVIRON_KEY    = "IS_GRACEFUL"
	GRACEFUL_ENVIRON_STRING = GRACEFUL_ENVIRON_KEY + "=1"
	GRACEFUL_LISTENER_FD    = 3
	OCSP_DEFAULT_EXPIRE     = time.Minute * 10
)

// HTTP server that supported graceful shutdown or restart
type Server struct {
	*http.Server

	listener net.Listener

	isGraceful   bool
	signalChan   chan os.Signal
	shutdownChan chan bool
	certFile     string
	certKey      string
	ocspExpire   time.Duration
}

func NewServer(addr string, handler http.Handler, readTimeout, writeTimeout time.Duration) *Server {
	isGraceful := false
	if os.Getenv(GRACEFUL_ENVIRON_KEY) != "" {
		isGraceful = true
	}

	return &Server{
		Server: &http.Server{
			Addr:    addr,
			Handler: handler,

			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
		},

		isGraceful:   isGraceful,
		signalChan:   make(chan os.Signal),
		shutdownChan: make(chan bool),
	}
}

func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		srv.Addr = ":http"
	}

	ln, err := srv.getNetListener()
	if err != nil {
		return err
	}

	srv.listener = ln

	if env == EnvDebug {
		fmt.Printf("The Server Is Runing: http://%s \n", srv.Addr)
	}

	return srv.Serve()
}

func (srv *Server) initServer(certFile string, keyFile string) {
	addr := srv.Addr
	if addr == "" {
		srv.Addr = ":https"
	}

	srv.certFile = certFile
	srv.certKey = keyFile
}

func (srv *Server) initConfig() *tls.Config {
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		config = srv.TLSConfig.Clone()
	}

	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	return config
}

func (srv *Server) ListenAndServeTLSOcsp(expire time.Duration, certFile, keyFile string) error {
	srv.initServer(certFile, keyFile)
	if expire > 0 {
		srv.ocspExpire = expire
	}

	config := srv.initConfig()
	configHasCert := len(config.Certificates) > 0 || config.GetCertificate != nil
	if !configHasCert {
		config.GetCertificate = srv.GetCertificateWithOcsp
		srv.asyncOcspCache()
	}

	ln, err := srv.getNetListener()
	if err != nil {
		return err
	}

	srv.listener = tls.NewListener(ln, config)

	if env == EnvDebug {
		fmt.Printf("The Server Is Runing: https://%s \n", srv.Addr)
	}

	return srv.Serve()
}

func (srv *Server) GetCertificateWithOcsp(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(srv.certFile, srv.certKey)
	if err != nil {
		return nil, err
	}

	if cache != nil {
		locker.RLock()
		cert.OCSPStaple = cache
		locker.RUnlock()
	}

	return &cert, nil
}

func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	srv.initServer(certFile, keyFile)
	config := srv.initConfig()

	configHasCert := len(config.Certificates) > 0 || config.GetCertificate != nil
	if !configHasCert || certFile != "" || keyFile != "" {
		config.Certificates = make([]tls.Certificate, 1)

		var err error
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}

	ln, err := srv.getNetListener()
	if err != nil {
		return err
	}

	srv.listener = tls.NewListener(ln, config)

	if env == EnvDebug {
		fmt.Printf("The Server Is Runing: https://%s \n", srv.Addr)
	}

	return srv.Serve()
}

func (srv *Server) Serve() error {
	go srv.handleSignals()
	err := srv.Server.Serve(srv.listener)

	srv.logf("waiting for connections closed.")
	<-srv.shutdownChan
	srv.logf("all connections closed.")

	return err
}

func (srv *Server) getNetListener() (net.Listener, error) {
	var ln net.Listener
	var err error

	if srv.isGraceful {
		file := os.NewFile(GRACEFUL_LISTENER_FD, "")
		ln, err = net.FileListener(file)
		if err != nil {
			err = fmt.Errorf("net.FileListener error: %v", err)
			return nil, err
		}
	} else {
		ln, err = net.Listen("tcp", srv.Addr)
		if err != nil {
			err = fmt.Errorf("net.Listen error: %v", err)
			return nil, err
		}
	}
	return ln, nil
}

func (srv *Server) handleSignals() {
	var sig os.Signal

	signal.Notify(
		srv.signalChan,
		syscall.SIGTERM,
		syscall.SIGUSR2,
	)

	for {
		sig = <-srv.signalChan
		switch sig {
		case syscall.SIGTERM:
			srv.logf("received SIGTERM, graceful shutting down HTTP server.")
			srv.shutdownHTTPServer()
		case syscall.SIGUSR2:
			srv.logf("received SIGUSR2, graceful restarting HTTP server.")

			if pid, err := srv.startNewProcess(); err != nil {
				srv.logf("start new process failed: %v, continue serving.", err)
			} else {
				srv.logf("start new process successed, the new pid is %d.", pid)
				srv.shutdownHTTPServer()
			}
		default:
		}
	}
}

func (srv *Server) shutdownHTTPServer() {
	if err := srv.Shutdown(context.Background()); err != nil {
		srv.logf("HTTP server shutdown error: %v", err)
	} else {
		srv.logf("HTTP server shutdown success.")
		srv.shutdownChan <- true
	}
}

// start new process to handle HTTP Connection
func (srv *Server) startNewProcess() (uintptr, error) {
	listenerFd, err := srv.getTCPListenerFd()
	if err != nil {
		return 0, fmt.Errorf("failed to get socket file descriptor: %v", err)
	}

	// set graceful restart env flag
	envs := []string{}
	for _, value := range os.Environ() {
		if value != GRACEFUL_ENVIRON_STRING {
			envs = append(envs, value)
		}
	}
	envs = append(envs, GRACEFUL_ENVIRON_STRING)

	execSpec := &syscall.ProcAttr{
		Env:   envs,
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd(), listenerFd},
	}

	fork, err := syscall.ForkExec(os.Args[0], os.Args, execSpec)
	if err != nil {
		return 0, fmt.Errorf("failed to forkexec: %v", err)
	}

	return uintptr(fork), nil
}

func (srv *Server) getTCPListenerFd() (uintptr, error) {
	file, err := srv.listener.(*net.TCPListener).File()
	if err != nil {
		return 0, err
	}
	return file.Fd(), nil
}

func (srv *Server) logf(format string, args ...interface{}) {
	pids := strconv.Itoa(os.Getpid())
	format = "[pid " + pids + "] " + format

	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (srv *Server) requestOCSP() error {
	cert, err := tls.LoadX509KeyPair(srv.certFile, srv.certKey)
	if err != nil {
		return err
	}

	if len(cert.Certificate) <= 1 {
		return errors.New("the cert have no leaf")
	}

	// 获取leaf证书，第一个证书
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	ocspServer := x509Cert.OCSPServer[0]
	if ocspServer == "" {
		return errors.New("ocsp server is empty")
	}

	x509Issuer, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		return err
	}

	ocspRequest, err := ocsp.CreateRequest(x509Cert, x509Issuer, nil)
	if err != nil {
		return err
	}

	ocspRequestReader := bytes.NewReader(ocspRequest)
	c := &http.Client{
		Timeout: time.Second * 60,
	}

	httpResponse, err := c.Post(ocspServer, "application/ocsp-request", ocspRequestReader)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("csp rsp code not 200: %s", httpResponse.Status))
	}

	ocspRsp, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return err
	}

	locker.Lock()
	cache = ocspRsp
	locker.Unlock()

	return nil
}

func (srv *Server) asyncOcspCache() {
	go srv.scheduleOcsp()
}

func (srv *Server) scheduleOcsp() {
	dur := OCSP_DEFAULT_EXPIRE
	if srv.ocspExpire > 0 {
		dur = srv.ocspExpire
	}

	// do at once right now
	go srv.requestOCSP()

	t := time.NewTicker(dur)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			// TODO log
			_ = srv.requestOCSP()
		}
	}
}
