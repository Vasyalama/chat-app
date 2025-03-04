package utils

import (
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

// Secret keys for signing the tokens (ensure these are kept secure)
var (
	accessTokenSecret  = []byte(os.Getenv("ACCESS_TOKEN_SECRET"))   // Use a strong, secret key for access token
	refreshTokenSecret = []byte(os.Getenv("REFRESH_TOKENT_SECRET")) // Use a strong, secret key for refresh token
)

// CustomClaims to store user information in the JWT
type CustomClaims struct {
	UserID uint `json:"userId"`
	jwt.StandardClaims
}

func GenerateTokens(userId uint) (string, string, time.Time, error) {
	accessTokenDurationStr := os.Getenv("ACCESS_TOKEN_EXPIRATION")
	refreshTokenDurationStr := os.Getenv("REFRESH_TOKEN_EXPIRATION")

	accessTokenExpiry, err := time.ParseDuration(accessTokenDurationStr)
	if err != nil {
		log.Printf("Invalid ACCESS_TOKEN_EXPIRATION duration: %v", err)
		return "", "", time.Now(), ErrInternalServer

	}
	refreshTokenExpiry, err := time.ParseDuration(refreshTokenDurationStr)
	if err != nil {
		log.Printf("Invalid REFRESH_TOKEN_EXPIRATION duration: %v", err)
		return "", "", time.Now(), ErrInternalServer
	}

	accessTokenExpiration := time.Now().Add(accessTokenExpiry)
	refreshTokenExpiration := time.Now().Add(refreshTokenExpiry)

	accessClaims := CustomClaims{
		UserID: userId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: accessTokenExpiration.Unix(),
			Issuer:    "chatapp",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(accessTokenSecret)
	if err != nil {
		log.Printf("Failed to sign access token: %v", err)
		return "", "", time.Now(), ErrInternalServer
	}

	// Create the Refresh Token
	refreshClaims := CustomClaims{
		UserID: userId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: refreshTokenExpiration.Unix(), // Set expiration time
			Issuer:    "chatapp",                     // Issuer of the token
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(refreshTokenSecret)
	if err != nil {
		log.Printf("Failed to sign refresh token: %v", err)
		return "", "", time.Now(), ErrInternalServer
	}

	return accessTokenString, refreshTokenString, refreshTokenExpiration, nil
}

func VerifyToken(tokenString string, isRefresh bool) (*CustomClaims, error) {
	secret := accessTokenSecret
	if isRefresh {
		secret = refreshTokenSecret
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("Unexpected signing method: %v", token.Header["alg"])
			return nil, ErrInternalServer // This error can be logged
		}
		return secret, nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok && ve.Errors&jwt.ValidationErrorExpired != 0 {
			log.Println("Token expired:", tokenString)
			return nil, ErrTokenExpired
		}

		log.Println("Error parsing token:", err)
		return nil, ErrTokenInvalid
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	log.Printf("Invalid token: %v", tokenString)
	return nil, ErrTokenInvalid
}
