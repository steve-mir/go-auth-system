package utils

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	AppUrl                   string        `mapstructure:"APP_URL"`
	DBDriver                 string        `mapstructure:"DB_DRIVER"`
	DBSource                 string        `mapstructure:"DB_SOURCE"`
	ServerAddress            string        `mapstructure:"SERVER_ADDRESS"`
	RefreshTokenSymmetricKey string        `mapstructure:"REFRESH_TOKEN_SYMMETRIC_KEY"`
	AccessTokenSymmetricKey  string        `mapstructure:"ACCESS_TOKEN_SYMMETRIC_KEY"`
	AccessTokenDuration      time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
	RefreshTokenDuration     time.Duration `mapstructure:"REFRESH_TOKEN_DURATION"`
	DBMaxIdleConn            int           `mapstructure:"DB_MAX_IDLE_CONN"`
	DBMaxOpenConn            int           `mapstructure:"DB_MAX_OPEN_CONN"`
	DBMaxIdleTime            int           `mapstructure:"DB_MAX_IDLE_TIME"`
	DBMaxLifeTime            int           `mapstructure:"DB_MAX_LIFE_TIME"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
