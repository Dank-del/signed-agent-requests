// Package sar signs public-read HTTP requests for the SAR Web Bot Auth profile.
package sar

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Version = "0.0.1"
const Profile = "signed-agent-requests/0.1"
const EmptyDigest = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"

// Options configures a provider identity and the destinations it may sign for.
// Clock is intended for clock synchronization and testing; the default is time.Now.
type Options struct {
	ProviderOrigin  string
	AllowedOrigins  []string
	LifetimeSeconds int
	Clock           func() time.Time
}

// Signer can use an Ed25519 private key or an isolated crypto.Signer implementation.
type Signer struct {
	key          crypto.Signer
	public       ed25519.PublicKey
	keyID        string
	provider     string
	destinations map[string]bool
	lifetime     int
	clock        func() time.Time
	nonce        func() ([]byte, error)
}

// ParsePrivateKey reads a single unencrypted PKCS#8 Ed25519 PEM key.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("a single PKCS#8 Ed25519 private key is required")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("an Ed25519 private key is required")
	}
	return key, nil
}

// NewSigner requires canonical HTTPS provider and destination origins.
func NewSigner(key crypto.Signer, options Options) (*Signer, error) {
	if key == nil {
		return nil, errors.New("an Ed25519 signer is required")
	}
	if private, ok := key.(ed25519.PrivateKey); ok {
		if len(private) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid Ed25519 key length")
		}
		key = ed25519.PrivateKey(append([]byte(nil), private...))
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("an Ed25519 signer is required")
	}
	provider, err := requireOrigin(options.ProviderOrigin)
	if err != nil {
		return nil, err
	}
	destinations := make(map[string]bool)
	for _, value := range options.AllowedOrigins {
		origin, err := requireOrigin(value)
		if err != nil {
			return nil, err
		}
		destinations[origin] = true
	}
	if len(destinations) == 0 {
		return nil, errors.New("configure at least one allowed destination")
	}
	lifetime := options.LifetimeSeconds
	if lifetime == 0 {
		lifetime = 60
	}
	if lifetime < 1 || lifetime > 60 {
		return nil, errors.New("signature lifetime must be between 1 and 60 seconds")
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	encoded := base64.RawURLEncoding.EncodeToString(public)
	thumbprint, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}{"Ed25519", "OKP", encoded})
	hash := sha256.Sum256(thumbprint)
	return &Signer{key: key, public: append(ed25519.PublicKey(nil), public...), keyID: base64.RawURLEncoding.EncodeToString(hash[:]), provider: provider,
		destinations: destinations, lifetime: lifetime, clock: clock, nonce: func() ([]byte, error) {
			value := make([]byte, 24)
			_, err := rand.Read(value)
			return value, err
		}}, nil
}

func (s *Signer) KeyID() string { return s.keyID }

// PublicJWK contains only the fields published in a provider key directory.
type PublicJWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Kid    string   `json:"kid"`
	Alg    string   `json:"alg"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
}

func (s *Signer) PublicJWK() PublicJWK {
	return PublicJWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(s.public),
		Kid: s.keyID, Alg: "ed25519", Use: "sig", KeyOps: []string{"verify"}}
}

var dnsName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var numericLabel = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]*)$`)

func authority(u *url.URL) (string, error) {
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.OmitHost {
		return "", errors.New("an absolute HTTPS URL without credentials is required")
	}
	parsed, err := url.Parse("https://" + u.Host)
	if err != nil || parsed.Host != u.Host || parsed.User != nil {
		return "", errors.New("invalid URL authority")
	}
	host := strings.ToLower(u.Hostname())
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" {
		host = address.String()
		if address.Is6() {
			host = "[" + host + "]"
		}
	} else {
		if !dnsName.MatchString(host) {
			return "", errors.New("use an ASCII DNS name or canonical IP address")
		}
		labels := strings.Split(strings.TrimSuffix(host, "."), ".")
		if numericLabel.MatchString(labels[len(labels)-1]) {
			return "", errors.New("ambiguous numeric host")
		}
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 0 || number > 65535 {
			return "", errors.New("invalid HTTPS port")
		}
		if number != 443 {
			host += ":" + strconv.Itoa(number)
		}
	}
	return host, nil
}

func requireOrigin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	host, err := authority(u)
	if err != nil {
		return "", err
	}
	origin := "https://" + host
	if value != origin {
		return "", errors.New("origins must be canonical HTTPS origins without paths, queries, or fragments")
	}
	return origin, nil
}

func publicRequest(request *http.Request) (*http.Request, string, error) {
	if request == nil || request.URL == nil || (request.Method != "GET" && request.Method != "HEAD") ||
		(request.Body != nil && request.Body != http.NoBody) || request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 || request.RequestURI != "" ||
		request.URL.Fragment != "" || request.URL.RawFragment != "" {
		return nil, "", errors.New("only public HTTPS GET/HEAD requests without content are supported")
	}
	host, err := authority(request.URL)
	if err != nil {
		return nil, "", err
	}
	if request.Host != "" && request.Host != request.URL.Host {
		return nil, "", errors.New("Host must match the URL authority")
	}
	for _, part := range strings.Split(request.URL.Path, "/") {
		if part == "." || part == ".." {
			return nil, "", errors.New("normalize dot segments before signing")
		}
	}
	for _, char := range request.URL.RawQuery {
		if char <= 32 || char >= 127 {
			return nil, "", errors.New("percent-encode query characters before signing")
		}
	}
	result := request.Clone(request.Context())
	result.URL.Host = host
	result.Host = host
	if result.URL.Path == "" {
		result.URL.Path = "/"
	}
	result.Header = make(http.Header)
	for name, values := range request.Header {
		lower := strings.ToLower(name)
		switch lower {
		case "authorization", "cookie", "content-encoding", "transfer-encoding":
			return nil, "", fmt.Errorf("%s is not supported by the public-read profile", name)
		case "content-length":
			if len(values) != 1 || values[0] != "0" {
				return nil, "", errors.New("Content-Length must be exactly 0")
			}
		case "host":
			if len(values) != 1 || values[0] != host {
				return nil, "", errors.New("Host must match the URL authority")
			}
		}
		canonical := http.CanonicalHeaderKey(name)
		result.Header[canonical] = append(result.Header[canonical], values...)
	}
	if err := checkSize(result); err != nil {
		return nil, "", err
	}
	return result, "https://" + host, nil
}

func checkSize(request *http.Request) error {
	size := 0
	for name, values := range request.Header {
		for _, value := range values {
			size += len(name) + len(value)
		}
	}
	if len(request.URL.String()) > 8192 || size > 16384 {
		return errors.New("request exceeds profile bounds")
	}
	return nil
}

// Sign clones the finalized request, preserving its context and encoded query.
// Send the returned request with automatic redirects disabled.
func (s *Signer) Sign(request *http.Request) (*http.Request, error) {
	result, origin, err := publicRequest(request)
	if err != nil {
		return nil, err
	}
	if !s.destinations[origin] {
		return nil, errors.New("destination is not authorized for this signer")
	}
	created := s.clock().Unix()
	if created < 0 || created > 999999999999999-int64(s.lifetime) {
		return nil, errors.New("invalid signing time")
	}
	nonce, err := s.nonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	agent := `agent="` + s.provider + `"`
	params := fmt.Sprintf(`("@method" "@target-uri" "content-digest" "signature-agent";key="agent");created=%d;expires=%d;keyid="%s";alg="ed25519";nonce="%s";tag="web-bot-auth"`,
		created, created+int64(s.lifetime), s.keyID, base64.RawURLEncoding.EncodeToString(nonce))
	base := `"@method": ` + result.Method + "\n" + `"@target-uri": ` + result.URL.String() + "\n" +
		`"content-digest": ` + EmptyDigest + "\n" + `"signature-agent";key="agent": "` + s.provider + "\"\n" +
		`"@signature-params": ` + params
	signature, err := s.key.Sign(rand.Reader, []byte(base), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("signer returned an invalid Ed25519 signature")
	}
	result.Header.Set("Content-Digest", EmptyDigest)
	result.Header.Set("Signature-Agent", agent)
	result.Header.Set("Signature-Input", "agent="+params)
	result.Header.Set("Signature", "agent=:"+base64.StdEncoding.EncodeToString(signature)+":")
	if err := checkSize(result); err != nil {
		return nil, err
	}
	return result, nil
}

type signingTransport struct {
	signer *Signer
	base   http.RoundTripper
}

func (t *signingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	signed, err := t.signer.Sign(request)
	if err != nil {
		return nil, err
	}
	return t.base.RoundTrip(signed)
}

// Client copies base and signs every outgoing request. Redirects are returned to
// the caller and cookies are not retained. A custom transport must preserve the
// signed URL/headers and must not add user credentials.
func (s *Signer) Client(base *http.Client) *http.Client {
	var result http.Client
	if base != nil {
		result = *base
	}
	transport := result.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	result.Transport = &signingTransport{signer: s, base: transport}
	result.Jar = nil
	result.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if result.Timeout == 0 {
		result.Timeout = 30 * time.Second
	}
	return &result
}
