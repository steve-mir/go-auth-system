package profiles

import (
	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/middlewares"
	profiles "github.com/steve-mir/go-auth-system/internal/app/profiles/controllers"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

const (
	defaultPath = "/user"
)

func Profile(config utils.Config, store *sqlc.Store, l *zap.Logger, r *gin.Engine) {

	// public := r.Group(defaultPath)

	// Private routes
	private := r.Group(defaultPath)
	private.Use(middlewares.AuthMiddlerWare(config, l))
	private.Use(middlewares.Verify(config, store, l))
	private.GET("/", profiles.UsersProfile(store, l))       // gets the profile of the currently logged in user
	private.PATCH("/", profiles.UpdateDetails(store, l))    // update the profile of the currently logged in user
	private.PATCH("/phone", profiles.UpdatePhone(store, l)) // update the phone number of the currently logged in user
	private.PATCH("/img", profiles.UpdateImg(store, l))     // update the image url number of the currently logged in user

}
