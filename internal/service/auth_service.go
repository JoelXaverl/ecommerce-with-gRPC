package service

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/entity"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/repository"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/utils"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pb/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type IAuthService interface {
	Register(ctx context.Context, request *auth.RegisterRequest) (*auth.RegisterResponse, error)
	Login(ctx context.Context, request *auth.LoginRequest) (*auth.LoginResponse, error)
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
		return nil, err
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
	newUser := entity.User{
		Id:        uuid.NewString(),
		FullName:  request.FullName,
		Email:     request.Email,
		Password:  string(hashedPassword),
		RoleCode:  entity.UserRoleCustomer,
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

// Login implements IAuthService.
func (as *authService) Login(ctx context.Context, request *auth.LoginRequest) (*auth.LoginResponse, error) {
	// check apakah email ada
	user, err := as.authRepository.GetUserByEmail(ctx, request.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return &auth.LoginResponse{
			Base: utils.BadRequestResponse("User is not registered"),
		}, nil
	}
	// check apakah password sama
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
    if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
        return nil, status.Errorf(codes.Unauthenticated, "Unauthenticated")
    }
    return nil, err
	}
	//generate jwt
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, entity.JwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: user.Id,
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour * 24)),
			IssuedAt: jwt.NewNumericDate(now),
		},
		Email:  user.Email,
		FullName: user.FullName,
		Role:   user.RoleCode,
	})
	secretKey := os.Getenv("JWT_SECRET")
	accessToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return nil, err
	}
	//kirim response
	return &auth.LoginResponse{
		Base: utils.SuccessResponse("Login successfull"),
		AccessToken: accessToken,
	}, nil
}

func NewAuthService(authRepository repository.IAuthRepository) IAuthService {
	return &authService{
		authRepository: authRepository,
	}
}
