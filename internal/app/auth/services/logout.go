package services

import (
	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

/*
*
An implementation would probably be, to store a so-called “blacklist” of all the tokens that are valid no more and have not expired yet.
You can use a DB that has TTL option on documents which would be set to the amount of time left until the token is expired.
Redis is a good option for this, that will allow fast in memory access to the list.
Then, in a middleware of some kind that runs on every authorized request, you should check if provided token is in The Blacklist.
🕵️‍ If it is you should throw an unauthorized error. And if it is not, let it go and the
JWT verification will handle it and identify if it is expired or still active.
*/
func LogoutUser(config utils.Config, store *sqlc.Store, ctx *gin.Context) error {
	// TODO: Log user out
	return nil
}
