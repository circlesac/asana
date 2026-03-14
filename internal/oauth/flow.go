package oauth

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

const (
	DefaultPort    = 8989
	RedirectURL    = "http://localhost:8989/callback"
	AuthURL        = "https://app.asana.com/-/oauth_authorize"
	TokenURL       = "https://app.asana.com/-/oauth_token"
	TimeoutSeconds = 120
)

type FlowResult struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

func RunOAuthFlow(clientID string) (*FlowResult, error) {
	if clientID == "" {
		clientID = os.Getenv("ASANA_CLIENT_ID")
	}
	if clientID == "" {
		return nil, fmt.Errorf("client ID required: set ASANA_CLIENT_ID env var or pass --client-id")
	}

	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	challenge := GenerateCodeChallenge(verifier)

	state, err := GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	resultCh, shutdown, err := StartCallbackServer(DefaultPort)
	if err != nil {
		return nil, err
	}
	defer shutdown()

	cfg := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    oauth2.Endpoint{AuthURL: AuthURL, TokenURL: TokenURL},
		RedirectURL: RedirectURL,
	}

	authURL := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("response_type", "code"),
	)

	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "Open this URL in your browser:\n%s\n\n", authURL)
	}

	fmt.Fprintln(os.Stderr, "Waiting for authentication...")

	select {
	case cb := <-resultCh:
		if cb.Err != nil {
			return nil, cb.Err
		}
		if cb.State != state {
			return nil, fmt.Errorf("state mismatch: possible CSRF attack")
		}

		token, err := cfg.Exchange(oauth2.NoContext, cb.Code,
			oauth2.SetAuthURLParam("code_verifier", verifier),
		)
		if err != nil {
			return nil, fmt.Errorf("token exchange failed: %w", err)
		}

		return &FlowResult{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
		}, nil

	case <-time.After(TimeoutSeconds * time.Second):
		return nil, fmt.Errorf("authentication timed out after %d seconds", TimeoutSeconds)
	}
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}
