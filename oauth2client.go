// This implementation is based on https://github.com/pilcrowonpaper/oslo
// by pilcrowonpaper, adapted for Go.

package oauth2client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type OAuth2Client struct {
	ClientID          string
	AuthorizeEndpoint string
	TokenEndpoint     string
	RedirectURI       string
}

type AuthorizationURLOptions struct {
	State               string
	CodeVerifier        string
	CodeChallengeMethod string
	Scopes              []string
}

type ValidateAuthorizationCodeOptions struct {
	CodeVerifier     string
	Credentials      string
	AuthenticateWith string
}

type RefreshAccessTokenOptions struct {
	Credentials      string
	AuthenticateWith string
	Scopes           []string
}

type TokenResponseBody struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type TokenErrorResponseBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewOAuth2Client(clientID, authorizeEndpoint, tokenEndpoint, redirectURI string) *OAuth2Client {
	return &OAuth2Client{
		ClientID:          clientID,
		AuthorizeEndpoint: authorizeEndpoint,
		TokenEndpoint:     tokenEndpoint,
		RedirectURI:       redirectURI,
	}
}

func (c *OAuth2Client) CreateAuthorizationURL(options AuthorizationURLOptions) (*url.URL, error) {
	authorizationUrl, err := url.Parse(c.AuthorizeEndpoint)
	if err != nil {
		return nil, err
	}

	q := authorizationUrl.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)

	if options.State != "" {
		q.Set("state", options.State)
	}

	if len(options.Scopes) > 0 {
		q.Set("scope", strings.Join(options.Scopes, " "))
	}

	if c.RedirectURI != "" {
		q.Set("redirect_uri", c.RedirectURI)
	}

	if options.CodeVerifier != "" {
		codeChallengeMethod := options.CodeChallengeMethod
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}

		if codeChallengeMethod == "S256" {
			h := sha256.New()
			h.Write([]byte(options.CodeVerifier))
			codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
			q.Set("code_challenge", codeChallenge)
			q.Set("code_challenge_method", "S256")
		} else if codeChallengeMethod == "plain" {
			q.Set("code_challenge", options.CodeVerifier)
			q.Set("code_challenge_method", "plain")
		} else {
			return nil, fmt.Errorf("invalid value for 'codeChallengeMethod': %s", codeChallengeMethod)
		}
	}

	authorizationUrl.RawQuery = q.Encode()
	return authorizationUrl, nil
}

func (c *OAuth2Client) ValidateAuthorizationCode(authorizationCode string, options ValidateAuthorizationCodeOptions) (*TokenResponseBody, error) {
	body := url.Values{}
	body.Set("code", authorizationCode)
	body.Set("client_id", c.ClientID)
	body.Set("grant_type", "authorization_code")

	if c.RedirectURI != "" {
		body.Set("redirect_uri", c.RedirectURI)
	}

	if options.CodeVerifier != "" {
		body.Set("code_verifier", options.CodeVerifier)
	}

	return c.sendTokenRequest(body, options.Credentials, options.AuthenticateWith)
}

func (c *OAuth2Client) RefreshAccessToken(refreshToken string, options RefreshAccessTokenOptions) (*TokenResponseBody, error) {
	body := url.Values{}
	body.Set("refresh_token", refreshToken)
	body.Set("client_id", c.ClientID)
	body.Set("grant_type", "refresh_token")

	if len(options.Scopes) > 0 {
		body.Set("scope", strings.Join(options.Scopes, " "))
	}

	return c.sendTokenRequest(body, options.Credentials, options.AuthenticateWith)
}

func (c *OAuth2Client) sendTokenRequest(body url.Values, credentials, authenticateWith string) (*TokenResponseBody, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", c.TokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-artic")

	if credentials != "" {
		if authenticateWith == "" {
			authenticateWith = "http_basic_auth"
		}

		if authenticateWith == "http_basic_auth" {
			req.SetBasicAuth(c.ClientID, credentials)
		} else if authenticateWith == "request_body" {
			body.Set("client_secret", credentials)
		} else {
			return nil, fmt.Errorf("invalid value for 'authenticateWith': %s", authenticateWith)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errorResp TokenErrorResponseBody
		if err := json.Unmarshal(bodyBytes, &errorResp); err == nil && errorResp.Error != "" {
			return nil, &OAuth2RequestError{
				Request:     req,
				ErrorCode:   errorResp.Error,
				Description: errorResp.ErrorDescription,
			}
		}
		return nil, &OAuth2RequestError{
			Request:   req,
			ErrorCode: fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
		}
	}

	var tokenResp TokenResponseBody
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}


func GenerateCodeVerifier() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, randomBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func GenerateState() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, randomBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

type OAuth2RequestError struct {
	Request     *http.Request
	ErrorCode   string
	Description string
}

func (e *OAuth2RequestError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("OAuth2 request error: %s - %s", e.ErrorCode, e.Description)
	}
	return fmt.Sprintf("OAuth2 request error: %s", e.ErrorCode)
}
