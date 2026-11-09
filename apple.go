// Package apple implements Sign in with Apple (OAuth2 + OpenID Connect).
// gtr package: passport-apple.
//
//	s, err := apple.New(apple.Config{
//	    ServicesID:  "com.example.web",          // the Services ID (client_id)
//	    TeamID:      "ABCDE12345",
//	    KeyID:       "XYZ987ZYX1",
//	    PrivateKey:  os.Getenv("APPLE_KEY_P8"),  // the .p8 key, PEM
//	    RedirectURL: "https://app.example.com/auth/apple/callback",
//	    StateKey:    []byte(os.Getenv("OAUTH_STATE_KEY")),
//	})
//	a.Use(s)
//
// Apple returns with a POST (response_mode=form_post): start the login
// with httpauth.NewFormPostState, read the callback with r.ParseForm and
// pass code, state and user to Callback; keep the callback route out of
// httpauth.CSRF (the state protects it). The client secret is a short JWT
// signed with the key for every code exchange. The profile comes from the
// verified id_token; Apple sends the user's name only on the first login, in
// the "user" form field, and Callback reads it from there.
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"passport"
	oauth2 "passport-oauth2"
)

// Apple endpoints.
const (
	AuthURL  = "https://appleid.apple.com/auth/authorize"
	TokenURL = "https://appleid.apple.com/auth/token"
	Issuer   = "https://appleid.apple.com"
	JWKSURL  = "https://appleid.apple.com/auth/keys"
)

// Config is what the Apple Developer account gives.
type Config struct {
	ServicesID  string // client_id
	TeamID      string
	KeyID       string
	PrivateKey  string // the .p8 file: a PEM "PRIVATE KEY" (ECDSA P-256)
	RedirectURL string
	// Scopes default to name and email (which needs form_post).
	Scopes []string
	// StateKey: see oauth2.Config.StateKey (shared by every instance).
	StateKey   []byte
	HTTPClient *http.Client

	// Endpoint overrides, for tests with oauth2test.
	AuthURL, TokenURL, Issuer, JWKSURL string
}

// Strategy is the "apple" passport.RedirectStrategy.
type Strategy struct {
	*oauth2.Strategy
}

// New checks the key and makes the strategy.
func New(c Config) (*Strategy, error) {
	block, _ := pem.Decode([]byte(c.PrivateKey))
	if block == nil {
		return nil, errors.New("apple: PrivateKey is not PEM (the .p8 file)")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apple: PrivateKey: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apple: PrivateKey is not an ECDSA key")
	}
	if c.ServicesID == "" || c.TeamID == "" || c.KeyID == "" {
		return nil, errors.New("apple: ServicesID, TeamID and KeyID are required")
	}
	or := func(v, def string) string {
		if v != "" {
			return v
		}
		return def
	}
	scopes := c.Scopes
	if scopes == nil {
		scopes = []string{"name", "email"}
	}
	issuer := or(c.Issuer, Issuer)
	cfg := oauth2.Config{
		ClientID: c.ServicesID, RedirectURL: c.RedirectURL,
		AuthURL: or(c.AuthURL, AuthURL), TokenURL: or(c.TokenURL, TokenURL),
		Scopes:     scopes,
		AuthParams: url.Values{"response_mode": {"form_post"}},
		HTTPClient: c.HTTPClient,
		PKCE:       true,
		OIDC:       &oauth2.OIDC{Issuer: issuer, JWKSURL: or(c.JWKSURL, JWKSURL)},
		StateKey:   c.StateKey,
		ClientSecretFunc: func() (string, error) {
			return clientSecret(key, c.KeyID, c.TeamID, c.ServicesID, issuer, time.Now())
		},
	}
	return &Strategy{oauth2.New("apple", cfg, MapProfile)}, nil
}

// Callback verifies the login and adds the name Apple sends on the first
// login (params["user"]: {"name":{"firstName":..,"lastName":..}}).
func (s *Strategy) Callback(ctx context.Context, params map[string]string) (*passport.Identity, error) {
	id, err := s.Strategy.Callback(ctx, params)
	if err != nil {
		return nil, err
	}
	var u struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
	}
	if raw := params["user"]; raw != "" && json.Unmarshal([]byte(raw), &u) == nil {
		id.Name = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
	}
	return id, nil
}

// MapProfile maps the id_token claims. Apple's email may be a private relay
// address (is_private_email); email_verified comes as "true".
func MapProfile(p map[string]any) (*passport.Identity, error) {
	return &passport.Identity{
		ProviderUserID: oauth2.String(p, "sub"),
		Email:          oauth2.String(p, "email"),
		EmailVerified:  oauth2.Bool(p, "email_verified"),
	}, nil
}

// clientSecret is the ES256 JWT Apple takes as client_secret (valid 5 minutes).
func clientSecret(key *ecdsa.PrivateKey, keyID, teamID, clientID, aud string, now time.Time) (string, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	c, _ := json.Marshal(map[string]any{"iss": teamID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "aud": aud, "sub": clientID})
	in := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(in))
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...)
	return in + "." + b64(sig), nil
}

var _ passport.RedirectStrategy = (*Strategy)(nil)
