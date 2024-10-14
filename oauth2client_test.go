package oauth2client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	// "net/url"
	"testing"
)

func TestCreateAuthorizationURL(t *testing.T) {
	client := NewOAuth2Client("client_id", "https://auth.example.com/authorize", "https://auth.example.com/token", "https://app.example.com/callback")

	tests := []struct {
		name    string
		options AuthorizationURLOptions
		want    string
	}{
		{
			name: "Basic URL",
			options: AuthorizationURLOptions{},
			want: "https://auth.example.com/authorize?client_id=client_id&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code",
		},
		{
			name: "With State and Scopes",
			options: AuthorizationURLOptions{
				State:  "some_state",
				Scopes: []string{"read", "write"},
			},
			want: "https://auth.example.com/authorize?client_id=client_id&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code&scope=read+write&state=some_state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.CreateAuthorizationURL(tt.options)
			if err != nil {
				t.Errorf("CreateAuthorizationURL() error = %v", err)
				return
			}
			if got.String() != tt.want {
				t.Errorf("CreateAuthorizationURL() = %v, want %v", got.String(), tt.want)
			}
		})
	}
}

func TestValidateAuthorizationCode(t *testing.T) {
	// Mock server to simulate token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("Error parsing form: %v", err)
		}
		if code := r.Form.Get("code"); code != "test_code" {
			t.Errorf("Expected code 'test_code', got %s", code)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponseBody{
			AccessToken: "access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	client := NewOAuth2Client("client_id", "https://auth.example.com/authorize", server.URL, "https://app.example.com/callback")

	resp, err := client.ValidateAuthorizationCode("test_code", ValidateAuthorizationCodeOptions{})
	if err != nil {
		t.Errorf("ValidateAuthorizationCode() error = %v", err)
		return
	}
	if resp.AccessToken != "access_token" {
		t.Errorf("Expected access token 'access_token', got %s", resp.AccessToken)
	}
}


func TestRefreshAccessToken(t *testing.T) {
	// Mock server to simulate token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("Error parsing form: %v", err)
		}
		if refreshToken := r.Form.Get("refresh_token"); refreshToken != "refresh_token" {
			t.Errorf("Expected refresh_token 'refresh_token', got %s", refreshToken)
		}
		json.NewEncoder(w).Encode(TokenResponseBody{
			AccessToken: "new_access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	client := NewOAuth2Client("client_id", "https://auth.example.com/authorize", server.URL, "https://app.example.com/callback")

	resp, err := client.RefreshAccessToken("refresh_token", RefreshAccessTokenOptions{})
	if err != nil {
		t.Errorf("RefreshAccessToken() error = %v", err)
		return
	}
	if resp.AccessToken != "new_access_token" {
		t.Errorf("Expected access token 'new_access_token', got %s", resp.AccessToken)
	}
}

func TestGenerateCodeVerifier(t *testing.T) {
	codeVerifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Errorf("GenerateCodeVerifier() error = %v", err)
		return
	}
	if len(codeVerifier) != 43 { // 32 bytes encoded in base64url without padding should be 43 characters
		t.Errorf("Expected code verifier length 43, got %d", len(codeVerifier))
	}
}

func TestGenerateState(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Errorf("GenerateState() error = %v", err)
		return
	}
	if len(state) != 43 { // 32 bytes encoded in base64url without padding should be 43 characters
		t.Errorf("Expected state length 43, got %d", len(state))
	}
}