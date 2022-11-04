package core

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/viper"
)

// CreateJWTToken create token
func CreateJWTToken(claims jwt.MapClaims) (string, error) {
	JWTTokenSecret := viper.GetString("jwt.token_secret")
	JWTExp := viper.GetInt("jwt.expaired_duration")

	var err error
	// extend claims data
	// claims["authorized"] = true
	claims["exp"] = time.Now().Add(time.Second * time.Duration(JWTExp)).Unix()
	JWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := JWT.SignedString([]byte(JWTTokenSecret))
	if err != nil {
		return "", err
	}
	return token, nil
}
