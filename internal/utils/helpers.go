package utils

import (
	"net"

	"github.com/sqlc-dev/pqtype"
)

// getIpAddr returns a pqtype.Inet representation of the client's IP address.
//
// It takes a string parameter, clientIP, which represents the client's IP address.
// It returns a pqtype.Inet value.
func GetIpAddr(clientIP string) pqtype.Inet {
	ip := net.ParseIP(clientIP)

	// if ip == nil {
	// 	 TODO: Handle the case where ctx.ClientIP() doesn't return a valid IP address
	// }

	inet := pqtype.Inet{
		IPNet: net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32), // If you're dealing with IPv4 addresses
		},
		Valid: true,
	}
	return inet
}
