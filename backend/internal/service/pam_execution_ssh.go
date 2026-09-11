// Linux target operations also run on non-Linux OneTerm servers.
package service

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/veops/oneterm/internal/model"
	"github.com/veops/oneterm/internal/repository"
	"github.com/veops/oneterm/pkg/secret"
)

var errPAMSSHIdentity = errors.New("SSH target identity does not match")

type PAMLinuxTarget struct {
	Address            string
	Username           string
	HostKeyFingerprint string
	UseSudo            bool
}

type PAMLinuxExecutor struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func pamLinuxUsername(username string) bool {
	return username != "" && len(username) <= 255 && !strings.ContainsAny(username, ":\x00\r\n")
}

func pamSSHConfig(target PAMLinuxTarget, username string, material secret.Material) (*ssh.ClientConfig, error) {
	host, port, err := net.SplitHostPort(target.Address)
	number, portErr := strconv.Atoi(port)
	fingerprint, keyErr := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(target.HostKeyFingerprint, "SHA256:"))
	if err != nil || portErr != nil || host == "" || number < 1 || number > 65535 || !pamLinuxUsername(username) ||
		!pamLinuxUsername(target.Username) || !strings.HasPrefix(target.HostKeyFingerprint, "SHA256:") || keyErr != nil || len(fingerprint) != 32 {
		return nil, ErrPAMInput
	}
	account := &model.Account{Account: username}
	switch material.Kind() {
	case secret.Password:
		account.AccountType, account.Password = model.AUTHMETHOD_PASSWORD, material.PasswordValue()
	case secret.SSHPrivateKey:
		account.AccountType, account.Pk, account.Phrase = model.AUTHMETHOD_PUBLICKEY, material.PrivateKeyValue(), material.PassphraseValue()
	default:
		return nil, ErrPAMInput
	}
	auth, err := repository.GetAuth(account)
	if err != nil {
		return nil, ErrPAMInput
	}
	return &ssh.ClientConfig{User: username, Auth: []ssh.AuthMethod{auth}, Timeout: 10 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if subtle.ConstantTimeCompare([]byte(ssh.FingerprintSHA256(key)), []byte(target.HostKeyFingerprint)) != 1 {
				return errPAMSSHIdentity
			}
			return nil
		}}, nil
}

func (executor PAMLinuxExecutor) connection(ctx context.Context, target PAMLinuxTarget, username string, material secret.Material) (*ssh.Client, func(), error) {
	configuration, err := pamSSHConfig(target, username, material)
	if err != nil {
		return nil, nil, err
	}
	dial := executor.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	connection, err := dial(ctx, "tcp", target.Address)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	transport, channels, requests, err := ssh.NewClientConn(connection, target.Address, configuration)
	if err != nil {
		stop()
		connection.Close()
		return nil, nil, err
	}
	client := ssh.NewClient(transport, channels, requests)
	return client, func() { stop(); client.Close() }, nil
}

func pamSSHFailure(err error, attempted bool) PAMExecutionResult {
	result := PAMExecutionResult{Code: PAMExecutionUnreachable, Attempted: attempted}
	if attempted {
		result.Code = PAMExecutionUnknown
	}
	switch {
	case errors.Is(err, ErrPAMInput):
		result.Code = PAMExecutionInvalidInput
	case errors.Is(err, errPAMSSHIdentity):
		result.Code = PAMExecutionIdentity
	case !attempted && strings.Contains(err.Error(), "unable to authenticate"):
		// x/crypto/ssh v0.37 returns this fixed client error, not a typed authentication error.
		result.Code = PAMExecutionAuthentication
	}
	return result
}

type pamBoundedOutput struct {
	data     []byte
	overflow bool
}

func (output *pamBoundedOutput) Write(value []byte) (int, error) {
	count := min(len(value), 32768-len(output.data))
	output.data = append(output.data, value[:count]...)
	output.overflow = output.overflow || count != len(value)
	return len(value), nil
}

func pamLinuxInspect(client *ssh.Client, username string) (string, string, PAMExecutionCode) {
	session, err := client.NewSession()
	if err != nil {
		return "", "", PAMExecutionUnreachable
	}
	defer session.Close()
	output := &pamBoundedOutput{}
	session.Stdin, session.Stdout, session.Stderr = strings.NewReader(username+"\n"), output, io.Discard
	// The account is stdin data, never a shell argument. Only the local files backend is queried.
	command := "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; LC_ALL=C; export LC_ALL; " +
		"IFS= read -r account || exit 1; id -un && id -u && getent -s files passwd \"$account\""
	if err := session.Run(command); err != nil {
		var exited *ssh.ExitError
		if !errors.As(err, &exited) {
			return "", "", pamSSHFailure(err, false).Code
		}
		return "", "", PAMExecutionUnsupported
	}
	if output.overflow {
		return "", "", PAMExecutionUnsupported
	}
	lines := strings.Split(strings.TrimSuffix(string(output.data), "\n"), "\n")
	if len(lines) != 3 {
		return "", "", PAMExecutionUnsupported
	}
	fields := strings.Split(lines[2], ":")
	if len(fields) != 7 || fields[0] != username {
		return "", "", PAMExecutionIdentity
	}
	return lines[0], lines[1], PAMExecutionVerified
}

func (executor PAMLinuxExecutor) Verify(ctx context.Context, target PAMLinuxTarget, material secret.Material) PAMExecutionResult {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client, close, err := executor.connection(ctx, target, target.Username, material)
	if err != nil {
		return pamSSHFailure(err, false)
	}
	defer close()
	username, _, code := pamLinuxInspect(client, target.Username)
	if code == PAMExecutionVerified && username != target.Username {
		code = PAMExecutionIdentity
	}
	return PAMExecutionResult{Code: code}
}

func pamLinuxPreflight(client *ssh.Client, command string) PAMExecutionResult {
	session, err := client.NewSession()
	if err != nil {
		return pamSSHFailure(err, false)
	}
	defer session.Close()
	session.Stdin, session.Stdout, session.Stderr = strings.NewReader(""), io.Discard, io.Discard
	// shadow-utils handles --help before opening password files or invoking PAM.
	if err := session.Run(command + " --help"); err != nil {
		var exited *ssh.ExitError
		if errors.As(err, &exited) {
			if exited.ExitStatus() == 126 || exited.ExitStatus() == 127 {
				return PAMExecutionResult{Code: PAMExecutionUnsupported}
			}
			return PAMExecutionResult{Code: PAMExecutionDenied}
		}
		return pamSSHFailure(err, false)
	}
	return PAMExecutionResult{Code: PAMExecutionVerified}
}

// Change needs root or an explicitly selected noninteractive sudo execution account.
// Passwords travel only over verified SSH stdin, with no PTY, command interpolation or target output logging.
func (executor PAMLinuxExecutor) Change(ctx context.Context, target PAMLinuxTarget, actor string,
	current, candidate secret.Material, before PAMBeforeChange) PAMExecutionResult {
	if before == nil || candidate.Kind() != secret.Password || candidate.PasswordValue() == "" ||
		len(candidate.PasswordValue()) > 1024 || strings.ContainsAny(candidate.PasswordValue(), "\x00\r\n") {
		return PAMExecutionResult{Code: PAMExecutionInvalidInput}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, close, err := executor.connection(ctx, target, actor, current)
	if err != nil {
		return pamSSHFailure(err, false)
	}
	defer close()
	username, uid, code := pamLinuxInspect(client, target.Username)
	if code != PAMExecutionVerified {
		return PAMExecutionResult{Code: code}
	}
	if username != actor {
		return PAMExecutionResult{Code: PAMExecutionIdentity}
	}
	command := "/usr/sbin/chpasswd"
	if target.UseSudo {
		command = "/usr/bin/sudo -n /usr/sbin/chpasswd"
	} else if uid != "0" {
		return PAMExecutionResult{Code: PAMExecutionDenied}
	}
	if result := pamLinuxPreflight(client, command); result.Code != PAMExecutionVerified {
		return result
	}
	session, err := client.NewSession()
	if err != nil {
		return pamSSHFailure(err, false)
	}
	defer session.Close()
	session.Stdin = strings.NewReader(target.Username + ":" + candidate.PasswordValue() + "\n")
	session.Stdout, session.Stderr = io.Discard, io.Discard
	if ctx.Err() != nil {
		return PAMExecutionResult{Code: PAMExecutionUnreachable}
	}
	if err := before(ctx); err != nil {
		return PAMExecutionResult{Code: PAMExecutionDenied}
	}
	if ctx.Err() != nil {
		return PAMExecutionResult{Code: PAMExecutionUnreachable}
	}
	if err := session.Run(command); err != nil {
		return pamSSHFailure(err, true)
	}
	return PAMExecutionResult{Code: PAMExecutionChanged, Attempted: true}
}
