package grpcmiddleware

import (
	"context"
	"log"

	jwtentity "github.com/JoelXaverl/ecommerce-go-grpc-be/internal/entity/jwt"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/utils"
	gocache "github.com/patrickmn/go-cache"
	"google.golang.org/grpc"
)

type authMiddleware struct {
	cacheService *gocache.Cache
}

func (am *authMiddleware) Middleware(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	if info.FullMethod == "/auth.AuthService/Login" || info.FullMethod == "/auth.AuthService/Register" {
		return handler(ctx, req)
	}

	// Ambil token dari metadata
	tokenStr, err := jwtentity.ParseTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Cek token dati Logout cache
	_, ok := am.cacheService.Get(tokenStr)
	if ok {
		return nil, utils.UnauthenticatedResponse()
	}

	// Parse Jwt nya hingga jadi entity
	claims, err := jwtentity.GetClaimFromToken(tokenStr)
	if err != nil {
		return nil, err
	}

	// Sematkan entity ke context
	ctx = claims.SetToContext(ctx)

	res, err := handler(ctx, req)

	return res, err
}

func NewAuthMiddleware(cacheSercive *gocache.Cache) *authMiddleware {
	return  &authMiddleware{
		cacheService: cacheSercive,
	}
}