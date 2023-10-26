package controllers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

func Logout(config utils.Config, store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		// Open a database connection
		// db, err := sql.Open(config.DBDriver, config.DBSource)
		// if err != nil {
		// 	log.Fatal("Cannot connect to db:", err)
		// }
		// defer db.Close()

		// store := sqlc.NewStore(db)

		fmt.Println("In logout")
		err := services.LogoutUser(config, store, ctx)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": "User logout successfully lol."})
	}
}
