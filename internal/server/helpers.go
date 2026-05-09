package server

import "github.com/gin-gonic/gin"

func responseErr(ctx *gin.Context, code int, message string) {
	ctx.JSON(code, gin.H{"error": message})
}
