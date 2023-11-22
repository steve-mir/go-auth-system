package gapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/steve-mir/go-auth-system/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (server *Server) LoginUser(ctx context.Context, req *pb.LoginUserRequest) (*pb.LoginUserResponse, error) {
	agent := server.extractMetadata(ctx).UserAgent
	ip := server.extractMetadata(ctx).ClientIP

	clientIP := utils.GetIpAddr(ip)
	log.Println("User ip", clientIP, " Agent", agent)

	err := HandleEmailPwdErrors(req.GetEmail(), req.GetPassword())
	if err != nil {
		server.l.Error("Email password error:", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "email password error: %s", err)
	}

	sessionID, err := uuid.NewRandom()
	if err != nil {
		server.l.Error("UUID error", zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "error creating uid %s", err)
	}

	//* Check login_failures for recent failures for this user from the current IP address. If too many, block login.

	user, err := server.store.GetUserByEmail(context.Background(), req.GetEmail())
	if err != nil {
		if err == sql.ErrNoRows {
			// err2 := recordFailedLogin(store, user.ID, agent, clientIP)
			server.l.Error("Error getting email "+req.GetEmail(), zap.Error(err))
			return nil, status.Errorf(codes.Unimplemented, "email or password incorrect %s", err)
		}
		// _ = recordFailedLogin(store, user.ID, agent, clientIP)
		server.l.Error("DB error", zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "email or password incorrect %s", err)

	}

	err = utils.CheckPassword(req.GetPassword(), user.PasswordHash)
	if err != nil {
		// _ = recordFailedLogin(store, user.ID, agent, clientIP)
		server.l.Error("wrong password", zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "email or password incorrect %s", err)
	}

	// Check if user should gain access
	err = checkAccountStat(user.IsSuspended, user.IsDeleted)
	if err != nil {
		server.l.Error("Checking account stat error", zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "checking account stat error %s", err)
	}

	// Refresh token
	refreshToken, refreshPayload, err := CreateUserToken(
		true, "", server.config, sessionID, true, user.Email, user.ID, user.IsEmailVerified.Bool,
		clientIP, agent, server.config.RefreshTokenDuration,
	)

	if err != nil {
		server.l.Error("Error creating Refresh token for "+req.GetEmail(), zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "error creating refresh token %s", err)
	}

	// Access token
	accessToken, accessPayload, err := CreateUserToken(
		false, refreshToken, server.config, sessionID, false, user.Email, user.ID, user.IsEmailVerified.Bool,
		clientIP, agent, server.config.AccessTokenDuration,
	)
	if err != nil {
		server.l.Error("Error creating Access token for "+req.GetEmail(), zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "error creating access token %s", err)
	}

	log.Println("SESSION ID", sessionID)
	_, err = server.store.CreateSession(context.Background(), sqlc.CreateSessionParams{

		ID:           sessionID, //refreshPayload.ID,
		UserID:       user.ID,
		Email:        sql.NullString{String: user.Email, Valid: true},
		RefreshToken: refreshToken,
		UserAgent:    agent,
		IpAddress:    clientIP,
		IsBlocked:    false,
		IsBreached:   false,
		ExpiresAt:    refreshPayload.Expires,
		CreatedAt: sql.NullTime{
			Time:  refreshPayload.IssuedAt,
			Valid: true,
		},
	})

	if err != nil {
		server.l.Error("Error creating Session for "+req.GetEmail(), zap.Error(err))
		log.Println("Session ID Error", err)
		return nil, status.Errorf(codes.Unimplemented, "error creating session id %s", err)
	}

	fmt.Println(accessToken)
	// ctx.SetCookie("accessToken", accessToken, 36000, "/", "http://localhost:9100/", false, true)

	//! 3 User logged in successfully. Record it
	err = recordLoginSuccess(server.store, user.ID, agent, clientIP)
	if err != nil {
		server.l.Error("Error creating login record for "+req.GetEmail(), zap.Error(err))
		return nil, status.Errorf(codes.Internal, "error creating login record %s", err)
	}

	// return resp
	return &pb.LoginUserResponse{
		User: &pb.User{
			Username: user.ID.String(),
			Email:    req.GetEmail(),
			FullName: req.GetEmail(),
		},
		AccessToken:          accessToken,
		AccessTokenExpiresAt: timestamppb.New(accessPayload.Expires),
	}, nil
}

// *********
func checkAccountStat(isSuspended bool, isDeleted bool) error {
	fmt.Printf("Is Suspended %v is deleted %v", isSuspended, isDeleted)
	if isSuspended {
		log.Println("Account deleted: ", isSuspended)
		return errors.New("account suspended")
	}

	// Check if user should gain access
	if isDeleted {
		log.Println("Account deleted: ", isDeleted)
		return errors.New("account suspended")
	}
	return nil
}

func CreateUserToken(isRefreshToken bool, refreshToken string, config utils.Config, sessionID uuid.UUID,
	isRefresh bool, email string, uid uuid.UUID, IsUserVerified bool,
	ip pqtype.Inet, agent string, duration time.Duration,
) (string, *token.Payload, error) {

	maker, err := token.NewPasetoMaker(utils.GetKeyForToken(config, isRefreshToken))
	if err != nil {
		log.Println("Error creating new paseto maker for ", email, "Error: ", err)
		return "", &token.Payload{}, err
	}

	return maker.CreateToken(
		token.PayloadData{
			// Role: "user",
			RefreshID:       refreshToken,
			IsRefresh:       isRefresh,
			SessionID:       sessionID,
			UserId:          uid,
			Username:        email,
			Email:           email,
			IsEmailVerified: IsUserVerified,
			Issuer:          "Settle in",
			Audience:        "website users",
			IP:              ip,
			UserAgent:       agent,
		}, duration)
}

func recordLoginSuccess(dbStore *sqlc.Store, userId uuid.UUID, userAgent string, ipAddrs pqtype.Inet) error {
	_, err := dbStore.CreateUserLogin(context.Background(), sqlc.CreateUserLoginParams{
		UserID: userId,
		LoginAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
		UserAgent: sql.NullString{
			String: userAgent,
			Valid:  true,
		},
		IpAddress: ipAddrs,
	})
	return err
}
