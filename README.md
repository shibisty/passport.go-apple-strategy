# passport-apple

Sign in with Apple for [`passport`](https://github.com/shibisty/passport.go), on
[`passport-oauth2`](https://github.com/shibisty/passport.go-oauth2-strategy). Go package: `apple`.

## Installation

```bash
gtr add github:shibisty/passport.go github:shibisty/passport.go-apple-strategy
```

## Usage

```go
s, err := apple.New(apple.Config{
    ServicesID:  "com.example.web", // client_id
    TeamID:      "ABCDE12345",
    KeyID:       "XYZ987ZYX1",
    PrivateKey:  os.Getenv("APPLE_KEY_P8"), // the .p8 file (PEM)
    RedirectURL: "https://app.example.com/auth/apple/callback",
    StateKey:    []byte(os.Getenv("OAUTH_STATE_KEY")),
})
a.Use(s)

// GET /auth/apple
state, _ := httpauth.NewFormPostState(w) // Apple returns with a POST
url, _ := a.RedirectURL("apple", state)

// POST /auth/apple/callback (keep it out of httpauth.CSRF: the state protects it)
r.ParseForm()
if err := httpauth.CheckState(w, r); err != nil { /* 400 */ }
id, err := a.Callback(ctx, "apple", map[string]string{
    "code": r.PostFormValue("code"), "state": r.PostFormValue("state"), "user": r.PostFormValue("user"),
})
```

- The client secret is a JWT signed with the team key (ES256), made for every code exchange.
- PKCE and OpenID Connect are on: the profile comes from the verified `id_token`
  (Apple's keys, `iss`, `aud`, `nonce`). `email` may be a private relay address.
- Apple sends the user's name only on the first login, in the `user` form field:
  `Callback` reads it into `Identity.Name`; store it then.

## License

MIT
