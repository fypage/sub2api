package repository

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
	"github.com/Wei-Shaw/sub2api/internal/util/urlvalidator"
)

const maxProxySubscriptionBytes = int64(2 << 20)

type ProxySubscriptionFetchRequest struct {
	URL          string
	ETag         string
	LastModified string
}

type ProxySubscriptionFetchResult struct {
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
}

type ProxySubscriptionFetcher struct {
	client *http.Client
}

func NewProxySubscriptionFetcher() *ProxySubscriptionFetcher {
	client, _ := httpclient.GetClient(httpclient.Options{
		Timeout: 20 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		ValidateResolvedIP: true, AllowPrivateHosts: false,
	})
	if client != nil {
		clone := *client
		clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("subscription redirect limit exceeded")
			}
			_, err := validateProxySubscriptionURL(req.URL.String())
			return err
		}
		client = &clone
	}
	return &ProxySubscriptionFetcher{client: client}
}

func (f *ProxySubscriptionFetcher) Fetch(ctx context.Context, request ProxySubscriptionFetchRequest) (*ProxySubscriptionFetchResult, error) {
	if f == nil || f.client == nil {
		return nil, fmt.Errorf("proxy subscription fetcher is unavailable")
	}
	normalized, err := validateProxySubscriptionURL(request.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy subscription url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalized, nil)
	if err != nil {
		return nil, fmt.Errorf("create proxy subscription request: %w", err)
	}
	req.Header.Set("Accept", "application/json,text/plain,*/*")
	req.Header.Set("User-Agent", "Sub2API-ProxySubscription/1")
	if etag := safeConditionalHeader(request.ETag); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if modified := safeConditionalHeader(request.LastModified); modified != "" {
		req.Header.Set("If-Modified-Since", modified)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch proxy subscription: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	result := &ProxySubscriptionFetchResult{
		ETag:         safeConditionalHeader(resp.Header.Get("ETag")),
		LastModified: safeConditionalHeader(resp.Header.Get("Last-Modified")),
	}
	if resp.StatusCode == http.StatusNotModified {
		result.NotModified = true
		return result, nil
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("proxy subscription returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxySubscriptionBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read proxy subscription: %w", err)
	}
	if int64(len(body)) > maxProxySubscriptionBytes {
		return nil, fmt.Errorf("proxy subscription exceeds %d bytes", maxProxySubscriptionBytes)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, fmt.Errorf("proxy subscription is empty")
	}
	result.Body = body
	return result, nil
}

func validateProxySubscriptionURL(raw string) (string, error) {
	normalized, err := urlvalidator.ValidateHTTPSURL(raw, urlvalidator.ValidationOptions{AllowPrivate: false})
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(normalized)
	if err != nil || parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("subscription URL contains forbidden components")
	}
	return normalized, nil
}

func safeConditionalHeader(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	return value
}
