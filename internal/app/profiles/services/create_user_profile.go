package profiles

import (
	"context"
	"database/sql"

	"github.com/steve-mir/go-auth-system/internal/app/auth"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

func CreateUserProfile(store *sqlc.Store,
	profileData auth.UserAuth,
) error {
	// Validate profileData

	err := store.CreateUserProfile(context.Background(), sqlc.CreateUserProfileParams{
		UserID:    profileData.UserId,
		FirstName: sql.NullString{String: profileData.FirstName, Valid: true},
		LastName:  sql.NullString{String: profileData.LastName, Valid: true},
		Phone:     sql.NullString{String: profileData.Phone, Valid: true},
		ImageUrl:  sql.NullString{String: profileData.ImageUrl, Valid: true},
	})
	if err != nil {
		return err
	}

	return nil
}

/**
package auth

type UserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=64,strong_password"`
	//
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	Phone     string `json:"phone" validate:"phone"`
}




err = profiles.CreateUserProfile(config, store, ctx, l, profiles.ProfileRequest{
		UserId:    sqlcUser.ID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}

*/
