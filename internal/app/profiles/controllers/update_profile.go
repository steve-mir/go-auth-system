package profiles

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"github.com/steve-mir/go-auth-system/internal/app/auth/middlewares"
	service "github.com/steve-mir/go-auth-system/internal/app/profiles/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"go.uber.org/zap"
)

func UpdateDetails(store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		if payload, exists := ctx.Get(middlewares.AuthorizationPayloadKey); exists {
			if data, ok := payload.(*token.Payload); ok {

				var req service.UpdateUserDetailsReq
				if err := ctx.ShouldBindJSON(&req); err != nil {
					ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// Validate
				validate := validator.New()
				if err := validate.Struct(req); err != nil {
					l.Error("Go validator error", zap.Error(err))
					ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// data.UserId
				err := service.UpdateUserDetails(store, data.UserId, req)
				if err != nil {
					l.Error("User not found", zap.Error(err))
					ctx.JSON(http.StatusFound, gin.H{"msg": "User not found"})
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"msg": "Profile updated successfully."})
				return
			}
		}
	}
}

func UpdatePhone(store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		if payload, exists := ctx.Get(middlewares.AuthorizationPayloadKey); exists {
			if data, ok := payload.(*token.Payload); ok {

				var req service.UpdatePhoneReq
				if err := ctx.ShouldBindJSON(&req); err != nil {
					ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// Validate
				validate := validator.New()
				if err := validate.Struct(req); err != nil {
					l.Error("Go validator error", zap.Error(err))
					ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// Send OTP to the phone number to verify ownership

				// data.UserId
				err := service.UpdatePhone(store, data.UserId, req)
				if err != nil {
					l.Error("User not found", zap.Error(err))
					ctx.JSON(http.StatusFound, gin.H{"msg": "User not found"})
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"msg": "Phone updated successfully."})
				return
			}
		}
	}
}

func UpdateImg(store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		if payload, exists := ctx.Get(middlewares.AuthorizationPayloadKey); exists {
			if data, ok := payload.(*token.Payload); ok {

				var req service.UpdateImgReq
				if err := ctx.ShouldBindJSON(&req); err != nil {
					ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// Validate
				validate := validator.New()
				if err := validate.Struct(req); err != nil {
					l.Error("Go validator error", zap.Error(err))
					ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}

				// Send OTP to the phone number to verify ownership

				// data.UserId
				err := service.UpdateImageUrl(store, data.UserId, req)
				if err != nil {
					l.Error("User not found", zap.Error(err))
					ctx.JSON(http.StatusFound, gin.H{"msg": "User not found"})
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"msg": "Image url updated successfully."})
				return
			}
		}
	}
}

func validatePhoneInput(l *zap.Logger, ctx *gin.Context, req service.UpdatePhoneReq) {

}

func validateImgInput(l *zap.Logger, ctx *gin.Context, req service.UpdateImgReq) {

}
