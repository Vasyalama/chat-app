package utils

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
	"log"
	"strings"
)

func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt) // Read random bytes from crypto/rand
	if err != nil {
		log.Println(err)
		return "", ErrInternalServer
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

func HashPasswordWithSalt(salt, password string, genSalt bool) (string, error) {
	if genSalt {
		var err error
		salt, err = GenerateSalt(16)
		if err != nil {
			return "", ErrInternalServer
		}
	}
	// Argon2 parameters
	timeCost := uint32(1)           // Time complexity (iterations)
	memoryCost := uint32(64 * 1024) // Memory cost in KiB (64 MB)
	parallelism := uint8(1)         // Parallelism factor (threads)
	keyLength := uint32(32)         // Length of the resulting hash

	// Hash the password with the salt using Argon2
	hash := argon2.Key([]byte(password), []byte(salt), timeCost, memoryCost, parallelism, keyLength)

	// Base64 encode the hash to store it as a string
	hashBase64 := base64.StdEncoding.EncodeToString(hash)

	// Combine the salt and hash as "salt+hash"
	passwordHash := salt + "$" + hashBase64

	return passwordHash, nil
}

func VerifyPassword(storedPassword string, inputPassword string) (bool, error) {
	var salt, storedHash string
	parts := strings.SplitN(storedPassword, "$", 2)
	if len(parts) != 2 {
		log.Println("hased password is not in correct format")
		return false, ErrInternalServer
	}
	salt = parts[0]
	storedHash = parts[1]

	hashInput, err := HashPasswordWithSalt(salt, inputPassword, false)
	if err != nil {
		return false, ErrInternalServer
	}

	return storedHash == hashInput[len(salt)+1:], nil
}
