package service

import (
	"context"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/repository"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/utils"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pb/auth"
)

type IAuthService interface {
	Register(ctx context.Context, request *auth.RegisterRequest) (*auth.RegisterResponse, error)
}

type authService struct {
	authRepository repository.IAuthRepository
}

func (as *authService) Register(ctx context.Context, request *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	// Ngecek email ke database
	user, err := as.authRepository.GetUserByEmail(ctx, request.Email)
	if err != nil {
		return  nil, err
	}
	// Apabila email sdh terdaftar, kita error-in
	if user != nil {
		return &auth.RegisterResponse{
			Base: utils.BadRequestResponse("User already exist"),
		}, nil
	}
	// kita juda perlu melakukan enkripsi password
	// Apabila email-nya blm terdaftar, kita insert ke db
	return &auth.RegisterResponse{}, nil
}

func NewAuthService(authRepository repository.IAuthRepository) IAuthService {
	return &authService{
		authRepository: authRepository,
	}
}