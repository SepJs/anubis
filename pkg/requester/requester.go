package requester

import (
	"net/http"
	"time"
)

// AnubisClient defines the main client structure for the scanner.
type AnubisClient struct {
	Client *http.Client
}

// NewClient returns a new client with optimized security/performance settings.
func NewClient() *AnubisClient {
	return &AnubisClient{
		Client: &http.Client{
			// Set a strict timeout to prevent the scanner from hanging on slow targets.
			Timeout: 10 * time.Second, 
			Transport: &http.Transport{
				MaxIdleConns:    100,
				IdleConnTimeout: 90 * time.Second,
			},
		},
	}
}

// SendRequest performs an HTTP GET request with custom headers.
func (c *AnubisClient) SendRequest(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	
	// Set custom User-Agent to identify the tool and bypass simple filters.
	req.Header.Set("User-Agent", "Anubis-Scanner/1.0 (Security Framework)")
	req.Header.Set("Connection", "close")

	return c.Client.Do(req)
}