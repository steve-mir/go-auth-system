package controllers

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

func Login(config utils.Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req userRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Open a database connection
		db, err := sql.Open(config.DBDriver, config.DBSource)
		if err != nil {
			log.Fatal("Cannot connect to db:", err)
		}
		defer db.Close()

		store := sqlc.NewStore(db)

		loginResp := services.LoginUser(config, store, ctx, req.Email, req.Password)
		if loginResp.Error != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": loginResp.Error.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": "User login successfully. ", "user": loginResp.User})
	}
}
