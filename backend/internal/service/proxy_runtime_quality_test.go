package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeRuntimeQualityClassificationBlocksChatGPTBackend(t *testing.T) {
	result := &ProxyQualityCheckResult{Score: 70, FailedCount: 1, Items: []ProxyQualityCheckItem{{Target: "chatgpt_backend", Status: "fail", HTTPStatus: 403}}}
	status, code, text := nativeRuntimeQualityClassification(result)
	require.Equal(t, "blocked", status)
	require.Equal(t, "chatgpt_backend_blocked", code)
	require.NotEmpty(t, text)
}

func TestNativeRuntimeQualityClassificationSeparatesGenericFailure(t *testing.T) {
	result := &ProxyQualityCheckResult{Score: 70, FailedCount: 1, Items: []ProxyQualityCheckItem{{Target: "anthropic", Status: "fail"}}}
	status, code, text := nativeRuntimeQualityClassification(result)
	require.Equal(t, "degraded", status)
	require.Equal(t, "quality_degraded", code)
	require.NotEmpty(t, text)

	result = &ProxyQualityCheckResult{Score: 100, PassedCount: 4}
	status, code, text = nativeRuntimeQualityClassification(result)
	require.Equal(t, "healthy", status)
	require.Empty(t, code)
	require.Empty(t, text)
}
