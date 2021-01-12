package sshserver

import (
	"strings"
	"testing"

	"github.com/containerssh/log"
)

func getLogger(t *testing.T) log.Logger {
	writer := &logWriter{
		t: t,
	}
	logger, err := log.New(
		log.Config{
			Level:  log.LevelDebug,
			Format: log.FormatText,
		},
		t.Name(),
		writer,
	)
	if err != nil {
		panic(err)
	}
	return logger
}

type logWriter struct {
	t *testing.T
}

func (l *logWriter) Write(p []byte) (n int, err error) {
	l.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
