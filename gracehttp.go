package gracehttp

import (
	"net/http"
	"time"
)

const (
	DEFAULT_READ_TIMEOUT  = 60 * time.Second
	DEFAULT_WRITE_TIMEOUT = DEFAULT_READ_TIMEOUT

	EnvDebug = "debug"
	EnvTest  = "test"
	EnvStage = "stage"
	EnvProd  = "prod"
)

var env = EnvProd

func SetEnv(mode string) {
	switch mode {
	case EnvDebug:
	case EnvTest:
	case EnvStage:
	case EnvProd:
		env = mode
		break
	default:
		env = EnvDebug
	}

	env = mode
}

// refer http.ListenAndServe
func ListenAndServe(addr string, handler http.Handler) error {
	return NewServer(addr, handler, DEFAULT_READ_TIMEOUT, DEFAULT_WRITE_TIMEOUT).ListenAndServe()
}

// refer http.ListenAndServeTLS
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	return NewServer(addr, handler, DEFAULT_READ_TIMEOUT, DEFAULT_WRITE_TIMEOUT).ListenAndServeTLS(certFile, keyFile)
}
