package profiles

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

type UpdateUserDetailsReq struct {
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
}

type UpdatePhoneReq struct {
	Phone string `json:"phone" validate:"required"` // TODO: Add phone validator
}

type UpdateImgReq struct {
	URL string `json:"url" validate:"required,url"`
}

func UpdateUserDetails(store *sqlc.Store,
	userId uuid.UUID, req UpdateUserDetailsReq,
) error {
	return store.UpdateUserProfile(context.Background(), sqlc.UpdateUserProfileParams{
		UserID:    userId,
		LastName:  sql.NullString{String: req.LastName, Valid: true},
		FirstName: sql.NullString{String: req.FirstName, Valid: true},
	})
}

func UpdatePhone(store *sqlc.Store,
	userId uuid.UUID, req UpdatePhoneReq,
) error {
	return store.UpdateUserPhone(context.Background(), sqlc.UpdateUserPhoneParams{
		UserID: userId,
		Phone:  sql.NullString{String: req.Phone, Valid: true},
	})
}

func UpdateImageUrl(store *sqlc.Store,
	userId uuid.UUID, req UpdateImgReq,
) error {
	return store.UpdateUserProfileImg(context.Background(), sqlc.UpdateUserProfileImgParams{
		UserID:   userId,
		ImageUrl: sql.NullString{String: req.URL, Valid: true},
	})
}

// -- name: UpdateUserProfileImg :exec
// UPDATE user_profiles
// SET image_url = $2
// WHERE user_id = $1;
