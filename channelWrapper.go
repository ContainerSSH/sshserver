package sshserver

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/containerssh/log"
	"golang.org/x/crypto/ssh"
)

type channelWrapper struct {
	channel        ssh.Channel
	logger         log.Logger
	lock           *sync.Mutex
	exitSent       bool
	exitSignalSent bool
	closedWrite    bool
	closed         bool
}

func (c *channelWrapper) Stdin() io.Reader {
	if c.channel == nil {
		panic(fmt.Errorf("BUG: stdin requested before channel is open"))
	}
	return c.channel
}

func (c *channelWrapper) Stdout() io.Writer {
	if c.channel == nil {
		panic(fmt.Errorf("BUG: stdout requested before channel is open"))
	}
	return c.channel
}

func (c *channelWrapper) Stderr() io.Writer {
	if c.channel == nil {
		panic(fmt.Errorf("BUG: stderr requested before channel is open"))
	}
	return c.channel.Stderr()
}

func (c *channelWrapper) ExitStatus(exitCode uint32) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: exit status sent before channel is open"))
	}
	c.logger.Debug(log.NewMessage(
		MExit,
		"Program exited with status %d",
		exitCode,
	).Label("exitCode", exitCode))
	if c.exitSent || c.closed {
		return
	}
	c.exitSent = true
	if _, err := c.channel.SendRequest(
		"exit-status",
		false,
		ssh.Marshal(exitStatusPayload{
			ExitStatus: exitCode,
		})); err != nil {
		if !errors.Is(err, io.EOF) {
			c.logger.Debug(log.Wrap(
				err,
				EExitCodeFailed,
				"Failed to send exit status to client",
			))
		}
	}
}

func (c *channelWrapper) ExitSignal(signal string, coreDumped bool, errorMessage string, languageTag string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: exit signal sent before channel is open"))
	}
	c.logger.Debug(log.NewMessage(
		MExitSignal,
		"Program exited with signal %s",
		signal,
	).Label("signal", signal).Label("coreDumped", coreDumped))
	if c.exitSignalSent || c.closed {
		return
	}
	c.exitSignalSent = true
	if _, err := c.channel.SendRequest(
		"exit-signal",
		false,
		ssh.Marshal(exitSignalPayload{
			Signal:       signal,
			CoreDumped:   coreDumped,
			ErrorMessage: errorMessage,
			LanguageTag:  languageTag,
		})); err != nil {
		if !errors.Is(err, io.EOF) {
			c.logger.Debug(log.Wrap(
				err,
				EExitCodeFailed,
				"Failed to send exit status to client",
			))
		}
	}
}

func (c *channelWrapper) CloseWrite() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: channel closed for writing before channel is open"))
	}
	if c.closed || c.closedWrite {
		return nil
	}
	return c.channel.CloseWrite()
}

func (c *channelWrapper) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: channel closed before channel is open"))
	}
	c.closed = true
	return c.channel.Close()
}

func (c *channelWrapper) onClose() {
	c.closed = true
}
