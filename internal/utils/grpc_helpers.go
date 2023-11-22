package utils

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func GetUserAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	var userAgent string
	if ok {
		userAgents := md.Get("user-agent")
		if len(userAgents) > 0 {
			userAgent = userAgents[0]
			// Use userAgent here
		} else {
			userAgent = ""
		}
	} else {
		userAgent = ""
	}
	return userAgent
}

func GetIP(ctx context.Context) string {
	var host string

	peer, ok := peer.FromContext(ctx)
	if ok {
		host, _, _ = net.SplitHostPort(peer.Addr.String())
		if host == "::1" {
			host = "127.0.0.1"
		}
	} else {
		// Handle error when it's not possible to get the client's IP
		log.Println("Failed to get ip addrs")
		host = ""
	}
	return host
}
