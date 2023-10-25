package services

import (
	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

func VerifyTokens(config utils.Config, store *sqlc.Store, ctx *gin.Context) error {
	return nil
}
