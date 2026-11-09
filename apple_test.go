package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"passport-oauth2/oauth2test"
)

func p8(t *testing.T, key any) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestLogin(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := oauth2test.NewProvider(t, map[string]any{"sub": "000123.abc", "email": "x@privaterelay.appleid.com", "email_verified": "true"})
	p.EnableOIDC(true)
	p.ClientID = "com.example.web"
	s, err := New(Config{
		ServicesID: "com.example.web", TeamID: "TEAM", KeyID: "KEY", PrivateKey: p8(t, key),
		RedirectURL: "https://app/cb", StateKey: []byte(strings.Repeat("k", 32)),
		AuthURL: p.AuthURL(), TokenURL: p.TokenURL(), Issuer: p.Issuer(), JWKSURL: p.JWKSURL(),
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(s.AuthCodeURL("st"))
	if u.Query().Get("response_mode") != "form_post" || u.Query().Get("scope") != "name email" {
		t.Fatalf("login URL: %s", u)
	}
	p.Authorize(u.String())
	// The client secret is the JWT Apple expects, signed with the team key.
	p.CheckSecret = func(sec string) bool {
		parts := strings.Split(sec, ".")
		if len(parts) != 3 {
			return false
		}
		var claims map[string]any
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		json.Unmarshal(raw, &claims)
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		return claims["iss"] == "TEAM" && claims["sub"] == "com.example.web" && claims["aud"] == p.Issuer() && len(sig) == 64 &&
			ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	id, err := s.Callback(context.Background(), map[string]string{
		"code": p.Code, "state": "st", "user": `{"name":{"firstName":"Ann","lastName":"Lee"},"email":"x"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id.ProviderUserID != "000123.abc" || !id.EmailVerified || id.Name != "Ann Lee" || id.Provider != "apple" {
		t.Fatalf("%+v", id)
	}
	if _, err := s.Callback(context.Background(), map[string]string{"code": "wrong", "state": "st"}); err == nil {
		t.Fatal("bad code accepted")
	}
}

func TestConfigErrors(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, c := range map[string]Config{
		"not PEM":    {ServicesID: "a", TeamID: "b", KeyID: "c", PrivateKey: "x"},
		"not PKCS8":  {ServicesID: "a", TeamID: "b", KeyID: "c", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}))},
		"RSA key":    {ServicesID: "a", TeamID: "b", KeyID: "c", PrivateKey: p8(t, rk)},
		"no team id": {ServicesID: "a", KeyID: "c", PrivateKey: p8(t, ec)},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	s, err := New(Config{ServicesID: "a", TeamID: "b", KeyID: "c", PrivateKey: p8(t, ec), Scopes: []string{}})
	if err != nil || s.Config().TokenURL != TokenURL || s.Config().OIDC.Issuer != Issuer {
		t.Fatalf("defaults: %v", err)
	}
	if _, err := clientSecret(ec, "k", "t", "c", "a", time.Now()); err != nil {
		t.Fatal(err)
	}
}
