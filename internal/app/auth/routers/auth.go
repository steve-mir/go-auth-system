package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/app/auth/controllers"
	"github.com/steve-mir/go-auth-system/internal/utils"
	// "github.com/steve-mir/simple_bank/api/controllers"
	// "github.com/steve-mir/simple_bank/util"
)

const (
	defaultPath = "/auth"
)

func Auth(config utils.Config, r *gin.Engine) {
	// Register a new user
	r.POST(defaultPath+"/register", controllers.Register(config))

	/*// Authenticate a user based on email/username and password.
	r.POST("user/login", controllers.Register(config))
	// Log the user out.
	r.POST("user/logout", controllers.Register(config))
	// Initiate a password reset by providing an email or username.
	r.POST("user/reset-password/request", controllers.Register(config))
	// Confirm a password reset with a reset token.
	r.POST("user/reset-password/confirm", controllers.Register(config))
	// Set up Two-Factor Authentication (2FA).
	r.POST("user/2fa/setup", controllers.Register(config))
	// Verify the 2FA code during login.
	r.POST("user/2fa/verify", controllers.Register(config))
	// Update the user's profile.
	r.PUT("user/profile", controllers.Register(config))
	// Retrieve the user's profile.
	r.GET("user/profile", controllers.Register(config))*/

}
