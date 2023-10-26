package profiles

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/middlewares"
	profiles "github.com/steve-mir/go-auth-system/internal/app/profiles"
	service "github.com/steve-mir/go-auth-system/internal/app/profiles/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"go.uber.org/zap"
)

func UsersProfile(store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		if payload, exists := ctx.Get(middlewares.AuthorizationPayloadKey); exists {
			if data, ok := payload.(*token.Payload); ok {
				// data.UserId
				user, err := service.GetUserProfile(store, data.UserId)
				if err != nil {
					l.Error("User not found", zap.Error(err))
					ctx.JSON(http.StatusFound, gin.H{"msg": "User not found"})
					return
				}
				ctx.JSON(http.StatusOK, gin.H{"msg": "User registered successfully. ", "user": profiles.User{
					UserId:    user.UserID,
					FirstName: user.FirstName.String,
					LastName:  user.LastName.String,
					Phone:     user.Phone.String,
					ImageUrl:  user.ImageUrl.String,
					// Email: user.,
				}})
				return
			}
		}
	}
}
