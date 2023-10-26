package profiles

import (
	"context"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
)

func GetUserProfile(store *sqlc.Store,
	userId uuid.UUID,
) (sqlc.UserProfile, error) {
	return store.GetUserProfileByUID(context.Background(), userId)
}
