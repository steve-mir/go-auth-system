package controllers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

func Logout(config utils.Config, db *sql.DB, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		fmt.Println("In logout")
		// Open a database connection
		// db, err := sql.Open(config.DBDriver, config.DBSource)
		// if err != nil {
		// 	log.Fatal("Cannot connect to db:", err)
		// }
		// defer db.Close()

		store := sqlc.NewStore(db) // TODO: Add store as dependency injector

		err := services.LogoutUser(config, store, ctx)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		verifyCode, _ := utils.GenerateUniqueToken("bbd2518c-1d94-472c-8563-cb5ab7608bf0")

		ctx.JSON(http.StatusOK, gin.H{"msg": "User logout successfully lol.", "link": verifyCode})
	}
}
