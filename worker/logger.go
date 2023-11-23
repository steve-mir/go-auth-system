package worker

import (
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Logger struct{}

func NewLogger() *Logger {
	return &Logger{}
}

func (logger *Logger) Print(level zerolog.Level, args ...interface{}) {
	log.WithLevel(level).Msg(fmt.Sprint(args...))
}

func (logger *Logger) Debug(arg ...interface{}) {
	logger.Print(zerolog.DebugLevel, arg...)
}

func (logger *Logger) Info(arg ...interface{}) {
	logger.Print(zerolog.InfoLevel, arg...)
}

func (logger *Logger) Warn(arg ...interface{}) {
	logger.Print(zerolog.WarnLevel, arg...)
}

func (logger *Logger) Error(arg ...interface{}) {
	logger.Print(zerolog.ErrorLevel, arg...)
}

func (logger *Logger) Fatal(arg ...interface{}) {
	logger.Print(zerolog.FatalLevel, arg...)
}
