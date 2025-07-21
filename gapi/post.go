package gapi

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/steve-mir/go-auth-system/cache"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/steve-mir/go-auth-system/pb"
)

type SocialMediaServer struct {
	pb.UnimplementedSocialMediaServiceServer
	config      utils.Config
	store       *sqlc.Store
	db          *sql.DB
	tokenMaker  token.Maker
	posts       []pb.Post
	postStreams []pb.SocialMediaService_PostStreamServer
	comments    []pb.Comment
	mu          sync.Mutex      // For thread-safety
	postCache   cache.PostCache // Add this line
}

func NewSocialMediaServer(db *sql.DB, config utils.Config) (*SocialMediaServer, error) {
	tokenMaker, err := token.NewPasetoMaker(config.AccessTokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker: %w", err)
	}
	// Create db store and pass as injector
	return &SocialMediaServer{
		config:      config,
		db:          db,
		store:       sqlc.NewStore(db),
		tokenMaker:  tokenMaker,
		posts:       []pb.Post{},
		comments:    []pb.Comment{},
		postStreams: []pb.SocialMediaService_PostStreamServer{},
		mu:          sync.Mutex{},
		postCache:   cache.NewRedisCache(config.RedisAddress /*config.RedisDB*/, 0, 5*time.Second), // Add this line
	}, nil
}

func (s *SocialMediaServer) PostStream(stream pb.SocialMediaService_PostStreamServer) error {
	s.mu.Lock()
	// Send all past posts to the new stream.
	// for _, post := range s.pastPosts {
	//     if err := stream.Send(&pb.PostMessage{Post: post}); err != nil {
	//         // handle error
	//     }
	// }

	// Load posts from Redis cache
	for _, post := range s.posts {
		log.Println("Fetching from redis")
		cachedPost := s.postCache.GetPost(stream.Context(), post.Id)
		if cachedPost != nil {
			if err := stream.Send(&pb.Post{Id: cachedPost.ID, Content: cachedPost.Content.String}); err != nil {
				return err
			}
		}
	}

	// Add the new stream to the postStreams slice.
	s.postStreams = append(s.postStreams, stream)
	s.mu.Unlock()

	<-stream.Context().Done()

	s.mu.Lock()
	for i, st := range s.postStreams {
		if st == stream {
			s.postStreams = append(s.postStreams[:i], s.postStreams[i+1:]...)
			break
		}
	}
	s.mu.Unlock()

	return stream.Context().Err()
}

func (s *SocialMediaServer) CreatePost(ctx context.Context, req *pb.CreatePostRequest) (*pb.CreatePostResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	post := pb.Post{Content: req.Content, Id: fmt.Sprint(len(s.posts) + 1)}
	s.posts = append(s.posts, post)

	// Save the post to Redis cache
	s.postCache.SetPost(ctx, post.Id, &sqlc.Post{
		ID: post.Id,
		Content: sql.NullString{
			String: post.Content,
			Valid:  true,
		},
	})

	for _, stream := range s.postStreams {
		if err := stream.Send(&post); err != nil {
			return nil, err
		}
	}

	return &pb.CreatePostResponse{PostId: post.Id}, nil
}

// Mine
func (s *SocialMediaServer) LiveComments(stream pb.SocialMediaService_LiveCommentsServer) error {
	for {
		comment, err := stream.Recv()
		if err != nil {
			return err
		}

		s.mu.Lock()
		s.comments = append(s.comments, *comment)
		s.mu.Unlock()

		// Echo the comment back to the client
		if err := stream.Send(comment); err != nil {
			return err
		}
	}
}
