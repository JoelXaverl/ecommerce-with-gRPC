package handler

import (
	"context"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/service"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/utils"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pb/auth"
)

type authHandler struct {
	auth.UnimplementedAuthServiceServer

	authService service.IAuthService
}

func (sh *authHandler) Register(ctx context.Context, request *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	validationerrors, err := utils.CheckValidation(request)
	if err != nil {
		return nil, err
	}
	if validationerrors != nil {
		return &auth.RegisterResponse{ 
			Base: utils.ValidationErrorResponse(validationerrors),
		}, nil
	}

	//Proses Register
	res, err := sh.authService.Register(ctx, request)
	if err != nil {
		return nil, err
	}
	
	return res, nil
}

func NewAuthHandler(authService service.IAuthService) *authHandler {
	return &authHandler{
		authService: authService,
	}
}