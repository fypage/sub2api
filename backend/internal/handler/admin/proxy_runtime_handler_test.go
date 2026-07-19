package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

func TestProxyRuntimePreviewRejectsDisabledFeatureWithoutEcho(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewProxyRuntimeHandler(nil)
	router.POST("/preview", handler.Preview)
	secret := "trojan://super-secret@example.com:443"
	request := httptest.NewRequest(http.MethodPost, "/preview", bytes.NewBufferString(`{"input":"`+secret+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code == http.StatusOK || strings.Contains(response.Body.String(), "super-secret") {
		t.Fatalf("disabled preview leaked input or succeeded: %d %s", response.Code, response.Body.String())
	}
}

func TestProxyRuntimeCreateRequiresAdministratorIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewProxyRuntimeHandler(nil)
	router.POST("/native", handler.Create)
	body := `{"input":"trojan://secret@example.com:443","fingerprint":"` + strings.Repeat("a", 64) + `","visibility":"private"}`
	request := httptest.NewRequest(http.MethodPost, "/native", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatalf("anonymous creation succeeded: %s", response.Body.String())
	}
}

func TestProxyRuntimeCreateReadsTypedAdminSubject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: 7})
		c.Next()
	})
	handler := NewProxyRuntimeHandler(nil)
	router.POST("/native", handler.Create)
	body := `{"input":"trojan://secret@example.com:443","fingerprint":"` + strings.Repeat("a", 64) + `","visibility":"private"}`
	request := httptest.NewRequest(http.MethodPost, "/native", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code == http.StatusUnauthorized {
		t.Fatalf("typed admin identity was not recognized: %s", response.Body.String())
	}
}
