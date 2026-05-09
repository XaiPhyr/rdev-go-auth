package server

import (
	"net/http"

	"github.com/XaiPhyr/rdev-go-auth/internal/dto"
	"github.com/XaiPhyr/rdev-go-auth/internal/service"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	svc *service.AuthService
}

func NewAuthHandler(svc *service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

func (s *AuthHandler) Login(ctx *gin.Context) {
	var req dto.LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		responseErr(ctx, http.StatusBadRequest, "invalid request")
		return
	}

	token, err := s.svc.Login(ctx.Request.Context(), req.Username, req.Password)
	if err != nil {
		responseErr(ctx, http.StatusUnauthorized, "invalid credentials")
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"token": token})
}
