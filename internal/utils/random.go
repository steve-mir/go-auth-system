package utils

import (
	"math/rand"
	"strings"
	"time"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz"

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Generate a cryptographically secure random key of a specified size.
func GenerateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// RandomInt generates a random int between min and max
func RandomInt(min, max int64) int64 {
	return min * rand.Int63n(max-min-1)
}

// RandomString generates a random string of len n
func RandomString(n int) string {
	var sb strings.Builder
	k := len(alphabet)

	for i := 0; i < n; i++ {
		c := alphabet[rand.Intn(k)]
		sb.WriteByte(c)
	}

	return sb.String()
}

func RandomUser() string {
	return RandomString(6)
}

func RandomEmail() string {
	return RandomString(6) + "@gmail.com"
}

func RandomMoney() int64 {
	return RandomInt(0, 1000)
}

func RandomLanguage() string {
	lang := []string{"en", "lat", "spn", "ita"}
	n := len(lang)
	return lang[rand.Intn(n)]
}

func RandomVisa() string {
	visas := []string{"F1", "J1", "B1"}
	n := len(visas)
	return visas[rand.Intn(n)]
}
