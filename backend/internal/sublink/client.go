package sublink

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) Convert(ctx context.Context, target string, nodes []string) (string, error) {
	if len(nodes) == 0 {
		return "", nil
	}
	payload := strings.Join(nodes, "\n")
	return c.ConvertFromURL(ctx, target, toDataURI(payload))
}

func (c *Client) ConvertFromURL(ctx context.Context, target, sourceURL string) (string, error) {
	if c.baseURL == "" {
		return "", errorsFor("sublink base url is empty")
	}
	sourceURL = strings.TrimSpace(sourceURL)
	if sourceURL == "" {
		return "", errorsFor("convert source url is empty")
	}

	query := url.Values{}
	query.Set("target", strings.TrimSpace(target))
	query.Set("url", sourceURL)
	endpoint := c.baseURL + "/sub?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build convert request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request convert endpoint: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read convert response: %w", err)
	}

	trimmed := strings.TrimSpace(string(respData))
	if resp.StatusCode >= 400 {
		if trimmed == "" {
			return "", fmt.Errorf("convert endpoint status %d", resp.StatusCode)
		}
		return "", fmt.Errorf("convert endpoint status %d: %s", resp.StatusCode, trimmed)
	}

	if trimmed == "" {
		return "", errorsFor("empty convert response")
	}
	if isConvertFailure(trimmed) {
		return "", errorsFor(trimmed)
	}

	return trimmed, nil
}

func toDataURI(payload string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	return "data:text/plain;base64," + encoded
}

func isConvertFailure(content string) bool {
	lower := strings.ToLower(strings.TrimSpace(content))
	return strings.Contains(lower, "no nodes were found")
}

func errorsFor(message string) error {
	return fmt.Errorf("sublink convert failed: %s", strings.TrimSpace(message))
}
