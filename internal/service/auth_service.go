package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/XaiPhyr/rdev-go-auth/internal/config"
	"github.com/XaiPhyr/rdev-go-auth/internal/data"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	r *data.UserRepository
	c *config.Config
}

func NewAuthService(r *data.UserRepository, c *config.Config) *AuthService {
	return &AuthService{r: r, c: c}
}

func (s *AuthService) Login(ctx context.Context, username, password string) (string, error) {
	user, err := s.r.GetUserByUsernameOrEmail(ctx, username)
	if err != nil {
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", err
	}

	return s.GenerateToken(user.ID)
}

func (s *AuthService) GenerateToken(userID int64) (string, error) {
	jwtKey := []byte(s.c.JWTSecretKey)
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func (s *AuthService) ParseToken(token string) (int64, error) {
	jwtKey := []byte(s.c.JWTSecretKey)

	t, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtKey, nil
	})

	if err != nil || !t.Valid {
		return 0, err
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		if userID, ok := claims["user_id"].(float64); ok {
			return int64(userID), nil
		}
	}

	return 0, jwt.ErrTokenInvalidClaims
}

func (s *AuthService) CanAccess(ctx context.Context, userID int64, requiredRole string) (bool, error) {
	allPerms, err := s.r.CheckUserPermission(ctx, userID, requiredRole)
	if err != nil {
		log.Println(fmt.Errorf("user permission error: %w", err))
		return false, err
	}

	// cacheKey := fmt.Sprintf("user:perms:%d", userID)

	// exists, err := s.redis.SIsMember(ctx, cacheKey, permSlug).Result()
	// if err == nil {
	// 	return exists, nil
	// }

	// if len(allPerms) > 0 {
	// 	s.redis.SAdd(ctx, cacheKey, allPerms)
	// 	s.redis.Expire(ctx, cacheKey, 1*time.Hour)
	// }

	// if slices.Contains(allPerms, requiredRole) {
	// 	return true, nil
	// }

	return allPerms, nil
}
