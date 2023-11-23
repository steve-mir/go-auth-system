package sqlc

import "context"

type CreateUserTxParams struct {
	CreateUserParams
	AfterCreate func(user User) error
}

type CreateUserTxResult struct {
	User User
}

func (store *Store) CreateUserTx(ctx context.Context, args CreateUserTxParams) (CreateUserTxResult, error) {
	var result CreateUserTxResult

	err := store.ExecTx(ctx, func(q *Queries) error {
		var err error

		result.User, err = q.CreateUser(ctx, args.CreateUserParams)
		if err != nil {
			return err
		}

		return args.AfterCreate(result.User)

	})

	return result, err
}
