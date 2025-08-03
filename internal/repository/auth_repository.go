package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/entity"
)

type IAuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
}

type authRepository struct {
	db *sql.DB
}

func (ar *authRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	row := ar.db.QueryRowContext(ctx, "SELECT id, email, password, full_name FROM users WHERE email = $1 AND is_deleted IS false", email)
	if row.Err() != nil {
		return nil, row.Err()
	}

	var user entity.User
	err := row.Scan(
		&user.Id,
		&user.Email,
		&user.Password,
		&user.FullName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		
		return nil, err
	}

	return &user, nil
}

func NewAuthRepository(db *sql.DB) IAuthRepository {
	return &authRepository{}
}