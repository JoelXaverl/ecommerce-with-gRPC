package jwt

import (
	"context"
	"fmt"
	"os"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/utils"
	"github.com/golang-jwt/jwt/v5"
)

type JwtEntityContextKey string

var JwtEntityContextKeyValue JwtEntityContextKey = "JwtEntity"

type JwtClaims struct {
	jwt.RegisteredClaims
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
}

func (jc *JwtClaims) SetToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, JwtEntityContextKeyValue, jc)
}

func GetClaimFromToken(token string) (*JwtClaims, error) {
	// kembalikan token tadi hingga menjadi entity jwt yang sudah dibuat
	tokenClaims, err := jwt.ParseWithClaims(token, &JwtClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}

		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return nil, utils.UnauthenticatedResponse()
	}

	if !tokenClaims.Valid {
		return nil, utils.UnauthenticatedResponse()
	}

	if claims, ok := tokenClaims.Claims.(*JwtClaims); ok {
		return  claims, nil
	}

	return nil, utils.UnauthenticatedResponse()
}
