// Test-only client used by the repository's cross-language HTTPS checks.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	sar "github.com/Dank-del/signed-agent-requests/sdks/go"
)

type input struct {
	KeyPath      string `json:"keyPath"`
	Provider     string `json:"providerOrigin"`
	Target       string `json:"targetUri"`
	Method       string `json:"method"`
	CAPath       string `json:"caPath"`
	Send         bool   `json:"send"`
	ClockSeconds *int64 `json:"clockSeconds"`
}

func run() error {
	var config input
	if err := json.NewDecoder(os.Stdin).Decode(&config); err != nil {
		return err
	}
	data, err := os.ReadFile(config.KeyPath)
	if err != nil {
		return err
	}
	key, err := sar.ParsePrivateKey(data)
	if err != nil {
		return err
	}
	target, err := url.Parse(config.Target)
	if err != nil {
		return err
	}
	options := sar.Options{ProviderOrigin: config.Provider, AllowedOrigins: []string{target.Scheme + "://" + target.Host}}
	if config.ClockSeconds != nil {
		options.Clock = func() time.Time { return time.Unix(*config.ClockSeconds, 0) }
	}
	signer, err := sar.NewSigner(key, options)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(config.Method, config.Target, nil)
	if err != nil {
		return err
	}
	output := make(map[string]any)
	var signed *http.Request
	if config.Send {
		certificate, err := os.ReadFile(config.CAPath)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certificate) {
			return errors.New("invalid test CA")
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
		defer transport.CloseIdleConnections()
		response, err := signer.Client(&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil {
			return err
		}
		if len(body) > 65536 {
			return errors.New("oversized test response")
		}
		output["status"], output["body"] = response.StatusCode, string(body)
		signed = response.Request
	} else {
		signed, err = signer.Sign(request)
		if err != nil {
			return err
		}
	}
	headers := make(map[string]string)
	for name, values := range signed.Header {
		headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	output["method"], output["url"], output["headers"] = signed.Method, signed.URL.String(), headers
	return json.NewEncoder(os.Stdout).Encode(output)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
