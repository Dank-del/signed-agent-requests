package sar

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureCase struct {
	Name          string            `json:"name"`
	Method        string            `json:"method"`
	TargetURI     string            `json:"targetUri"`
	Created       int64             `json:"created"`
	Nonce         string            `json:"nonce"`
	SignatureBase string            `json:"signatureBase"`
	Headers       map[string]string `json:"headers"`
}
type fixtureData struct {
	Provider string        `json:"providerOrigin"`
	Seed     string        `json:"privateKeySeedHex"`
	KeyID    string        `json:"keyId"`
	Cases    []fixtureCase `json:"cases"`
}

func fixture(t *testing.T) (fixtureData, ed25519.PrivateKey) {
	t.Helper()
	data, err := os.ReadFile("testdata/signing-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var value fixtureData
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(value.Seed)
	if err != nil {
		t.Fatal(err)
	}
	return value, ed25519.NewKeyFromSeed(seed)
}

func newSigner(t *testing.T, origins ...string) *Signer {
	t.Helper()
	f, key := fixture(t)
	signer, err := NewSigner(key, Options{ProviderOrigin: f.Provider, AllowedOrigins: origins,
		Clock: func() time.Time { return time.Unix(f.Cases[0].Created, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestSharedVectors(t *testing.T) {
	f, key := fixture(t)
	for _, vector := range f.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			signer := newSigner(t, "https://shop.example")
			nonce, err := base64.RawURLEncoding.DecodeString(vector.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			signer.nonce = func() ([]byte, error) { return nonce, nil }
			request, err := http.NewRequest(vector.Method, vector.TargetURI, nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Signature", "old signature")
			signed, err := signer.Sign(request)
			if err != nil {
				t.Fatal(err)
			}
			if signer.KeyID() != f.KeyID {
				t.Fatal("incorrect JWK thumbprint")
			}
			if signed.URL.String() != vector.TargetURI {
				t.Fatal("encoded URI changed")
			}
			for name, expected := range vector.Headers {
				if actual := signed.Header.Get(name); actual != expected {
					t.Errorf("%s differs: %s", name, actual)
				}
			}
			if request.Header.Get("Signature") != "old signature" {
				t.Fatal("input request mutated")
			}
			encoded := strings.TrimSuffix(strings.TrimPrefix(signed.Header.Get("Signature"), "agent=:"), ":")
			signature, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(vector.SignatureBase), signature) {
				t.Fatal("independent signature verification failed")
			}
		})
	}
}

func TestRejectsUnsupportedRequests(t *testing.T) {
	signer := newSigner(t, "https://shop.example")
	for _, item := range []struct{ name, method, uri, header, value string }{
		{"http", "GET", "http://shop.example/", "", ""},
		{"credentials", "GET", "https://user:secret@shop.example/", "", ""},
		{"destination", "GET", "https://other.example/", "", ""},
		{"fragment", "GET", "https://shop.example/#section", "", ""},
		{"write", "POST", "https://shop.example/", "", ""},
		{"cookie", "GET", "https://shop.example/", "cookie", ""},
		{"authorization", "GET", "https://shop.example/", "authorization", "Bearer example"},
		{"encoding", "GET", "https://shop.example/", "content-encoding", "gzip"},
		{"length", "GET", "https://shop.example/", "content-length", "1"},
		{"host", "GET", "https://shop.example/", "host", "other.example"},
		{"dot-segments", "GET", "https://shop.example/a/%2e%2e/b", "", ""},
		{"query-space", "GET", "https://shop.example/?q=two words", "", ""},
	} {
		t.Run(item.name, func(t *testing.T) {
			request, err := http.NewRequest(item.method, item.uri, nil)
			if err != nil {
				t.Fatal(err)
			}
			if item.header != "" {
				request.Header[item.header] = []string{item.value}
			}
			if _, err := signer.Sign(request); err == nil {
				t.Fatal("unsupported request accepted")
			}
		})
	}
	request, _ := http.NewRequest("GET", "https://shop.example/", strings.NewReader("content"))
	if _, err := signer.Sign(request); err == nil {
		t.Fatal("body accepted")
	}
	request, _ = http.NewRequest("GET", "https://shop.example/", nil)
	request.Host = "other.example"
	if _, err := signer.Sign(request); err == nil {
		t.Fatal("Host override accepted")
	}
	request.Host = request.URL.Host
	request.Header.Set("X-Padding", strings.Repeat("x", 16000))
	if _, err := signer.Sign(request); err == nil {
		t.Fatal("oversized signed headers accepted")
	}
}

func TestConfigurationAndPEM(t *testing.T) {
	f, key := fixture(t)
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	if err != nil || !loaded.Equal(key) {
		t.Fatal("PKCS#8 loading failed")
	}
	if _, err := ParsePrivateKey([]byte("invalid")); err == nil {
		t.Fatal("invalid key accepted")
	}
	for _, options := range []Options{
		{ProviderOrigin: f.Provider, AllowedOrigins: nil},
		{ProviderOrigin: f.Provider + "/", AllowedOrigins: []string{"https://shop.example"}},
		{ProviderOrigin: f.Provider, AllowedOrigins: []string{"http://shop.example"}},
		{ProviderOrigin: f.Provider, AllowedOrigins: []string{"https://shop.example"}, LifetimeSeconds: 61},
	} {
		if _, err := NewSigner(key, options); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := NewSigner(ed25519.PrivateKey{}, Options{}); err == nil {
		t.Fatal("short key accepted")
	}
	public, err := json.Marshal(newSigner(t, "https://shop.example").PublicJWK())
	if err != nil {
		t.Fatal(err)
	}
	var published map[string]any
	if err := json.Unmarshal(public, &published); err != nil {
		t.Fatal(err)
	}
	if published["kid"] != f.KeyID || published["d"] != nil {
		t.Fatal("invalid public directory data")
	}
}

func TestCanonicalRootAndFreshConcurrentNonces(t *testing.T) {
	signer := newSigner(t, "https://shop.example")
	request, _ := http.NewRequest("GET", "https://SHOP.EXAMPLE:443", nil)
	signed, err := signer.Sign(request)
	if err != nil {
		t.Fatal(err)
	}
	if signed.URL.String() != "https://shop.example/" || signed.Host != "shop.example" {
		t.Fatal("incorrect wire authority/root path")
	}
	if request.URL.Host != "SHOP.EXAMPLE:443" {
		t.Fatal("input URL mutated")
	}
	var mutex sync.Mutex
	nonces := make(map[string]bool)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			value, err := signer.Sign(request)
			if err != nil {
				t.Error(err)
				return
			}
			mutex.Lock()
			defer mutex.Unlock()
			input := value.Header.Get("Signature-Input")
			if nonces[input] {
				t.Error("nonce reused")
			}
			nonces[input] = true
		}()
	}
	group.Wait()
}

func TestClientPreservesTLSAndStopsRedirects(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Signature") == "" {
			t.Error("missing signature")
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("unexpected cookie")
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer server.Close()
	signer := newSigner(t, server.URL)
	base := server.Client()
	base.Jar, _ = cookiejar.New(nil)
	target, _ := http.NewRequest("GET", server.URL, nil)
	base.Jar.SetCookies(target.URL, []*http.Cookie{{Name: "session", Value: "example"}})
	response, err := signer.Client(base).Get(server.URL + "/first")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || calls != 1 {
		t.Fatal("redirect followed")
	}
}
