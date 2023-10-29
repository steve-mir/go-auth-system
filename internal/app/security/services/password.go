package security

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	security "github.com/steve-mir/go-auth-system/internal/app/security"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

var (
	pwdLength = 33
	res       = "if an account exists a password reset email will be sent to you."
)

type HashResult struct {
	HashedPassword string
	Err            error
}

func SendPasswordResetEmail(config utils.Config, store *sqlc.Store, ctx *gin.Context, l *zap.Logger, email string) (string, error) {

	pwdResetCode, err := utils.GenerateUniqueToken(pwdLength)
	if err != nil {
		return "", err
	}

	link := config.AppUrl + "/password-reset/new?token=" + pwdResetCode
	msg := "Hello " + email + ", Use this link to reset your password.\n" + link
	fmt.Println(msg)
	fmt.Println("Sent to ", email)

	// Check if email exists
	_, err = store.GetUserByEmail(context.Background(), email)
	if err != nil {
		l.Error("Email doest not exist", zap.Error(err))
		return res, errors.New(res)
	}

	// TODO: send email here.

	// Add link to db
	err = store.CreatePasswordResetRequest(context.Background(), sqlc.CreatePasswordResetRequestParams{
		Email:     email,
		Token:     pwdResetCode,
		Used:      sql.NullBool{Valid: true, Bool: false},
		ExpiresAt: time.Now().Add(time.Minute * 15),
	})
	if err != nil {
		l.Error("Error creating email verification request", zap.Error(err))
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "an unexpected error occurred"})
		ctx.Abort()

		return res, errors.New("an unexpected error occurred")

	}

	l.Info("Reset password", zap.String("password reset", link))
	return res, nil

}

func ResetPassword(config utils.Config, store *sqlc.Store, link string, l *zap.Logger, req security.NewPwdRequest) error {
	// TODO: Check later
	// fmt.Println("PASSWORD RESET URL: ", len(link))
	// fmt.Println(link)
	// fmt.Println("PASSWORD RESET URL: ", pwdLength)
	// if len(link) != pwdLength {
	// 	l.Error("password reset error", zap.Error(errors.New("invalid token")))
	// 	return errors.New("invalid token")
	// }

	linkData, err := store.GetPasswordResetRequestByToken(context.Background(), link)
	if err != nil {
		l.Error("error getting password reset token from db", zap.Error(err))
		return err
	}

	if condition := linkData.ExpiresAt.Before(time.Now()); condition {
		return fmt.Errorf("token expired")
	}

	if linkData.Used.Bool {
		return fmt.Errorf("token already used")
	}

	// ! 1 Get User
	user, err := getUser(store, l, linkData.Email)
	if err != nil {
		return err
	}

	// ! 2 Check old password
	if err = utils.CheckPassword(req.Password, user.PasswordHash); err == nil {
		l.Error("wrong password", zap.Error(err))
		return errors.New("cannot use old password")
	}

	// ! 3 Hash password concurrently
	hashedPwdChan := make(chan HashResult)

	go func() {
		hashedPwd, err := utils.HashPassword(req.Password)
		result := HashResult{HashedPassword: hashedPwd, Err: err}
		hashedPwdChan <- result
	}()

	// To receive the result and error:
	result := <-hashedPwdChan
	if result.Err != nil {
		l.Error("Error while hashing password", zap.Error(result.Err))
		return result.Err
	}

	//

	// ! 4 Use transaction to update these
	err = store.UpdatePasswordResetRequestByToken(context.Background(), sqlc.UpdatePasswordResetRequestByTokenParams{
		Token: link,
		Used:  sql.NullBool{Bool: true, Valid: true},
	})
	if err != nil {
		l.Error("error updating token status", zap.Error(err))
		return err
	}

	// Change password
	err = store.UpdateUserPassword(context.Background(), sqlc.UpdateUserPasswordParams{
		Email:        linkData.Email,
		PasswordHash: result.HashedPassword,
	})
	if err != nil {
		l.Error("error updating user status", zap.Error(err))
		return err
	}

	// Commit transaction

	return nil

}

func getUser(store *sqlc.Store, l *zap.Logger, email string) (sqlc.User, error) {
	user, err := store.GetUserByEmail(context.Background(), email)
	if err != nil {
		if err == sql.ErrNoRows {
			l.Error("Error getting email "+email, zap.Error(err))
			return sqlc.User{}, errors.New("email not found")
		}
		l.Error("DB error", zap.Error(err))
		return sqlc.User{}, errors.New("email not found")
	}
	return user, nil
}
