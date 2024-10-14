# go-oauth2client

This is a Go implementation of an OAuth2 client, providing functionality for authorization code flow and token refresh.

## Credit

This implementation is based on the original work by [pilcrowonpaper](https://github.com/pilcrowonpaper) in the [oslo](https://github.com/pilcrowonpaper/oslo) project.

## Installation

To install this package, use:

```
go get github.com/naimulh247/go-oauth2client
```

## Usage

Here's a basic example of how to use this OAuth2 client:

```go
package main

import (
	"fmt"
	"log"

	"github.com/naimulh247/go-oauth2client"
)

func main() {
	client := oauth2client.NewOAuth2Client(
		"your-client-id",
		"https://auth.example.com/authorize",
		"https://auth.example.com/token",
		"https://your-app.com/callback",
	)

	// Generate an authorization URL
	authURL, err := client.CreateAuthorizationURL(oauth2client.AuthorizationURLOptions{
		State:  "your-state",
		Scopes: []string{"read", "write"},
	})
	if err != nil {
		log.Fatalf("Error creating authorization URL: %v", err)
	}
	fmt.Printf("Authorization URL: %s\n", authURL)

	// After receiving the authorization code...
	token, err := client.ValidateAuthorizationCode("received-code", oauth2client.ValidateAuthorizationCodeOptions{})
	if err != nil {
		log.Fatalf("Error validating authorization code: %v", err)
	}
	fmt.Printf("Received token: %+v\n", token)

	// Refreshing a token
	newToken, err := client.RefreshAccessToken("refresh-token", oauth2client.RefreshAccessTokenOptions{})
	if err != nil {
		log.Fatalf("Error refreshing token: %v", err)
	}
	fmt.Printf("New token: %+v\n", newToken)
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- [pilcrowonpaper/oslo](https://github.com/pilcrowonpaper/oslo) - The original implementation that helped implement this Go version.