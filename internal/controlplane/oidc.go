package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func newOIDCTokenVerifier(ctx context.Context, config Config) (auth.TokenVerifier, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	discoveryCtx, cancel := context.WithTimeout(oidc.ClientContext(ctx, httpClient), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryCtx, config.OIDCIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover configured OIDC issuer: %w", err)
	}
	verifierCtx := oidc.ClientContext(context.Background(), httpClient)
	verifier := provider.VerifierContext(verifierCtx, &oidc.Config{ClientID: config.OIDCAudience})

	return func(ctx context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
		idToken, err := verifier.Verify(ctx, rawToken)
		if err != nil || idToken.Issuer != config.OIDCIssuerURL || idToken.Subject == "" {
			return nil, auth.ErrInvalidToken
		}
		var claims struct {
			Scope  string   `json:"scope"`
			Scopes []string `json:"scp"`
		}
		if err := idToken.Claims(&claims); err != nil {
			return nil, auth.ErrInvalidToken
		}
		scopes := append(strings.Fields(claims.Scope), claims.Scopes...)
		sessionID := sha256.Sum256([]byte(idToken.Issuer + "\x00" + idToken.Subject))
		return &auth.TokenInfo{
			UserID:     hex.EncodeToString(sessionID[:]),
			Expiration: idToken.Expiry,
			Scopes:     scopes,
			Extra: map[string]any{
				"issuer":  idToken.Issuer,
				"subject": idToken.Subject,
			},
		}, nil
	}, nil
}
