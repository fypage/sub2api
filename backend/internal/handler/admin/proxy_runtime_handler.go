package admin

import (
	"context"
	"strconv"
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type ProxyRuntimeHandler struct {
	admin service.ProxyRuntimeAdminService
}

func NewProxyRuntimeHandler(admin service.ProxyRuntimeAdminService) *ProxyRuntimeHandler {
	return &ProxyRuntimeHandler{admin: admin}
}

type proxyRuntimePreviewRequest struct {
	Input string `json:"input" binding:"required"`
}

type proxyRuntimeCreateRequest struct {
	Name          string `json:"name"`
	Input         string `json:"input" binding:"required"`
	Fingerprint   string `json:"fingerprint" binding:"required,len=64,hexadecimal"`
	Visibility    string `json:"visibility" binding:"required,oneof=private public"`
	FallbackMode  string `json:"fallback_mode" binding:"omitempty,oneof=none proxy direct"`
	BackupProxyID *int64 `json:"backup_proxy_id"`
}

func (h *ProxyRuntimeHandler) Preview(c *gin.Context) {
	var request proxyRuntimePreviewRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	if h == nil || h.admin == nil {
		response.ErrorFrom(c, infraerrors.BadRequest("NATIVE_PROXY_RUNTIME_DISABLED", "native proxy runtime is disabled"))
		return
	}
	previews, err := h.admin.Preview(c.Request.Context(), request.Input)
	if err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("NATIVE_PROXY_INPUT_INVALID", "invalid native proxy input"))
		return
	}
	response.Success(c, previews)
}

func (h *ProxyRuntimeHandler) Create(c *gin.Context) {
	var request proxyRuntimeCreateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	if h == nil || h.admin == nil {
		response.ErrorFrom(c, infraerrors.BadRequest("NATIVE_PROXY_RUNTIME_DISABLED", "native proxy runtime is disabled"))
		return
	}
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok || subject.UserID <= 0 {
		response.ErrorFrom(c, infraerrors.Unauthorized("ADMIN_IDENTITY_REQUIRED", "administrator identity is required"))
		return
	}
	fingerprint := strings.ToLower(strings.TrimSpace(request.Fingerprint))
	executeAdminIdempotentJSON(c, "admin.proxy-runtimes.create", request, service.DefaultWriteIdempotencyTTL(), func(ctx context.Context) (any, error) {
		ownerID := subject.UserID
		created, err := h.admin.Create(ctx, service.ProxyRuntimeCreateRequest{
			Name: strings.TrimSpace(request.Name), OwnerUserID: &ownerID,
			Input: request.Input, Fingerprint: fingerprint, Visibility: request.Visibility,
			FallbackMode: strings.TrimSpace(request.FallbackMode), BackupProxyID: request.BackupProxyID,
		})
		if err != nil {
			if created != nil {
				return gin.H{"proxy_id": created.ProxyID, "runtime_id": created.RuntimeID, "status": "error"}, nil
			}
			return nil, infraerrors.BadRequest("NATIVE_PROXY_CREATE_FAILED", "native proxy creation failed")
		}
		return gin.H{"proxy_id": created.ProxyID, "runtime_id": created.RuntimeID, "status": created.Status}, nil
	})
}

func (h *ProxyRuntimeHandler) Status(c *gin.Context) {
	proxyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || proxyID <= 0 {
		response.BadRequest(c, "Invalid proxy ID")
		return
	}
	status, err := h.admin.Status(c.Request.Context(), proxyID)
	if err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("NATIVE_PROXY_STATUS_UNAVAILABLE", "native proxy runtime status unavailable"))
		return
	}
	response.Success(c, status)
}

func (h *ProxyRuntimeHandler) Start(c *gin.Context) {
	h.control(c, true)
}

func (h *ProxyRuntimeHandler) Stop(c *gin.Context) {
	h.control(c, false)
}

func (h *ProxyRuntimeHandler) control(c *gin.Context, start bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid runtime ID")
		return
	}
	if h == nil || h.admin == nil {
		response.ErrorFrom(c, infraerrors.BadRequest("NATIVE_PROXY_RUNTIME_DISABLED", "native proxy runtime is disabled"))
		return
	}
	var operationErr error
	if start {
		operationErr = h.admin.Start(c.Request.Context(), id)
	} else {
		operationErr = h.admin.Stop(c.Request.Context(), id)
	}
	if operationErr != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("NATIVE_PROXY_CONTROL_FAILED", "native proxy control failed"))
		return
	}
	response.Success(c, gin.H{"runtime_id": id, "status": map[bool]string{true: "starting", false: "stopped"}[start]})
}
