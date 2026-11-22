package api

import (
	"context"

	"github.com/dertown/network-control-centre/internal/certdeploy"
	"github.com/dertown/network-control-centre/internal/recursorfix"
)

// SetFixDial replaces the SSH dial of the Recursor fix and returns a function that restores it.
func SetFixDial(d func(ctx context.Context, o certdeploy.SSHOptions) (recursorfix.Conn, string, error)) func() {
	old := fixDialSSH
	fixDialSSH = d
	return func() { fixDialSSH = old }
}
