// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package logger provides helper functions to configure and use a global logger
package logger

import (
	"log"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/signalapp/svr2/config"
)

// init sets up reasonable logging defaults for tests / non-main
func init() {
	Init(config.Default())
}

// Init configures global loggers accessed with logging functions in this module.
// Optionaly provided fields will bind some key/value pairs to the global logger
func Init(cfg *config.Config) {
	z, err := cfg.Log.Build(zap.AddCallerSkip(1))
	if err != nil {
		log.Fatalf("zap init: %v", err)
	}
	zap.ReplaceGlobals(z)
}

// WithGlobal binds some key/value pairs to the global logger
func WithGlobal(fields ...zapcore.Field) {
	zap.ReplaceGlobals(zap.L().With(fields...))
}

// With returns a logger with some bound key/value pairs
func With(keysAndValues ...interface{}) *Logger {
	return &Logger{zap.S().With(keysAndValues...)}
}

// Sync flushes any buffered logs. Applications should call Sync before program exit.
func Sync() {
	zap.L().Sync()
}

type Logger struct {
	*zap.SugaredLogger
}

// wrappers around sugared zap logging methods that use the zap global logger

func Infow(msg string, keysAndValues ...interface{})  { zap.S().Infow(msg, keysAndValues...) }
func Infof(template string, args ...interface{})      { zap.S().Infof(template, args...) }
func Debugw(msg string, keysAndValues ...interface{}) { zap.S().Debugw(msg, keysAndValues...) }
func Debugf(template string, args ...interface{})     { zap.S().Debugf(template, args...) }
func Warnw(msg string, keysAndValues ...interface{})  { zap.S().Warnw(msg, keysAndValues...) }
func Warnf(template string, args ...interface{})      { zap.S().Warnf(template, args...) }
func Errorw(msg string, keysAndValues ...interface{}) { zap.S().Errorw(msg, keysAndValues...) }
func Errorf(template string, args ...interface{})     { zap.S().Errorf(template, args...) }
func Fatalw(msg string, keysAndValues ...interface{}) { zap.S().Fatalw(msg, keysAndValues...) }
func Fatalf(template string, args ...interface{})     { zap.S().Fatalf(template, args...) }
