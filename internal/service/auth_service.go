package service

import (
	"context"
	"time"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/entity"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/repository"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/utils"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pb/auth"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type IAuthService interface {
	Register(ctx context.Context, request *auth.RegisterRequest) (*auth.RegisterResponse, error)
}

type authService struct {
	authRepository repository.IAuthRepository
}

func (as *authService) Register(ctx context.Context, request *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	if request.Password != request.PwsswordConfirmation {
		return &auth.RegisterResponse{
			Base: utils.BadRequestResponse("Password is not matched"),
		}, nil
	}
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
	// kita juda perlu melakukan Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		return nil, err
	}
	// Apabila email-nya blm terdaftar, kita insert ke db
	newUser := entity.User {
		Id: uuid.NewString(),
		FullName: request.FullName,
		Email: request.Email,
		Password: string(hashedPassword),
		RoleCode: entity.UserRoleCustomer,
		CreatedAt: time.Now(),
		CreatedBy: &request.FullName,
	}
	err = as.authRepository.InsertUser(ctx, &newUser)
	if err != nil {
		return nil, err
	}

	return &auth.RegisterResponse{
		Base: utils.SuccessResponse("User is registered"),
	}, nil
}

func NewAuthService(authRepository repository.IAuthRepository) IAuthService {
	return &authService{
		authRepository: authRepository,
	}
}