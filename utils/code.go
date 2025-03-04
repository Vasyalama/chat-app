package utils

import (
	"crypto/rand"
	"log"
	"math/big"
)

func GenerateRandom4DigitCode() (int, error) {
	code, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		log.Println("Error generating random 4 digit code:", err)
		return -1, ErrInternalServer
	}

	return int(code.Int64()) + 1000, nil
}
