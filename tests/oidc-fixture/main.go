// Command oidc-fixture is a disposable identity issuer for deployment tests.
// It must not be used outside a local or CI acceptance run.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	keyID    = "ufm-deployment-test-key"
	audience = "ubuntu-fleet-manager-ci"
	subject  = "deployment-smoke-user"
)

func main() {
	listenAddress := flag.String("listen", "0.0.0.0:18443", "TLS listen address")
	issuerURL := flag.String("issuer", "", "exact HTTPS issuer URL")
	certificatePath := flag.String("cert", "", "TLS certificate path")
	privateKeyPath := flag.String("key", "", "TLS private key path")
	flag.Parse()
	if *issuerURL == "" || *certificatePath == "" || *privateKeyPath == "" {
		fmt.Fprintln(os.Stderr, "--issuer, --cert, and --key are required")
		os.Exit(2)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate test issuer key:", err)
		os.Exit(1)
	}
	certificate, err := tls.LoadX509KeyPair(*certificatePath, *privateKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load test issuer certificate:", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                *issuerURL,
			"jwks_uri":                              *issuerURL + "/jwks",
			"authorization_endpoint":                *issuerURL + "/authorize",
			"token_endpoint":                        *issuerURL + "/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		public := privateKey.PublicKey
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": keyID,
			"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now().UTC()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss":   *issuerURL,
			"sub":   subject,
			"aud":   audience,
			"iat":   now.Unix(),
			"exp":   now.Add(10 * time.Minute).Unix(),
			"scope": "openid",
		})
		token.Header["kid"] = keyID
		encoded, err := token.SignedString(privateKey)
		if err != nil {
			http.Error(w, "unable to sign test token", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"access_token": encoded, "token_type": "Bearer"})
	})

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen for test issuer:", err)
		os.Exit(1)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(tls.NewListener(listener, server.TLSConfig)); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "serve test issuer:", err)
		os.Exit(1)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
