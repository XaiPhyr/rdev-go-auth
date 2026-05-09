package server

import (
	"github.com/XaiPhyr/rdev-go-auth/internal/config"
	"github.com/XaiPhyr/rdev-go-auth/internal/data"
	"github.com/XaiPhyr/rdev-go-auth/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/uptrace/bun"
)

func Container(r *gin.Engine, db *bun.DB, cfg *config.Config) {
	userRepo := data.NewUserRepository(db)
	authSvc := service.NewAuthService(userRepo, cfg)

	apiVersion := r.Group("/api/v1")
	setupAuthRoutes(apiVersion, authSvc)
}

func setupAuthRoutes(rg *gin.RouterGroup, authSvc *service.AuthService) {
	authHandler := NewAuthHandler(authSvc)

	rg.POST("/login", authHandler.Login)
}
