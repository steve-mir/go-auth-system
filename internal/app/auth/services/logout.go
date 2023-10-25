package services

import (
	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

func LogoutUser(config utils.Config, store *sqlc.Store, ctx *gin.Context) error {
	// TODO: Log user out
	return nil
}
