package repository

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/httpclient"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/Wei-Shaw/sub2api/internal/util/httputil"
)

type runtimeQualityGate struct {
	exitProber interface {
		ProbeProxy(context.Context, string) (*service.ProxyExitInfo, int64, error)
	}
}

func NewRuntimeQualityGate(prober service.ProxyExitInfoProber) RuntimeQualityGate {
	return &runtimeQualityGate{exitProber: prober}
}

func (g *runtimeQualityGate) Check(ctx context.Context, proxyURL string) (RuntimeQualityResult, error) {
	if g == nil || g.exitProber == nil || strings.TrimSpace(proxyURL) == "" {
		return RuntimeQualityResult{}, fmt.Errorf("runtime quality gate is not configured")
	}
	exitInfo, _, err := g.exitProber.ProbeProxy(ctx, proxyURL)
	if err != nil {
		return RuntimeQualityResult{}, fmt.Errorf("probe native proxy exit: %w", err)
	}
	client, err := httpclient.GetClient(httpclient.Options{ProxyURL: proxyURL, Timeout: 15 * time.Second, ResponseHeaderTimeout: 10 * time.Second})
	if err != nil {
		return RuntimeQualityResult{}, fmt.Errorf("create native proxy quality client: %w", err)
	}
	openAI := probeRuntimeTarget(ctx, client, "https://api.openai.com/v1/models")
	chatGPT := probeRuntimeTarget(ctx, client, "https://chatgpt.com/backend-api/models")
	result := RuntimeQualityResult{Status: "healthy", Score: 100, ExitIP: exitInfo.IP, CountryCode: exitInfo.CountryCode}
	if chatGPT.challenge || chatGPT.status == http.StatusForbidden {
		result.Status, result.Score = "blocked", 20
		result.ErrorCode, result.ErrorText = "chatgpt_backend_blocked", "ChatGPT backend is blocked on this exit"
		return result, nil
	}
	if chatGPT.err != nil || chatGPT.status != http.StatusUnauthorized {
		result.Status, result.Score = "degraded", 55
		result.ErrorCode, result.ErrorText = "chatgpt_backend_unavailable", "ChatGPT backend quality probe failed"
		return result, nil
	}
	if openAI.err != nil || (openAI.status != http.StatusUnauthorized && openAI.status != http.StatusForbidden) {
		result.Status, result.Score = "degraded", 70
		result.ErrorCode, result.ErrorText = "openai_api_unavailable", "OpenAI API quality probe failed"
	}
	return result, nil
}

type runtimeProbeResult struct {
	status    int
	challenge bool
	err       error
}

func probeRuntimeTarget(ctx context.Context, client *http.Client, url string) runtimeProbeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return runtimeProbeResult{err: err}
	}
	req.Header.Set("Accept", "application/json,text/html,*/*")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return runtimeProbeResult{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil {
		return runtimeProbeResult{status: resp.StatusCode, err: err}
	}
	if len(body) > 8192 {
		body = body[:8192]
	}
	return runtimeProbeResult{status: resp.StatusCode, challenge: httputil.IsCloudflareChallengeResponse(resp.StatusCode, resp.Header, body)}
}
