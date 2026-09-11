package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	mysql "github.com/go-sql-driver/mysql"

	"github.com/veops/oneterm/pkg/secret"
)

type PAMMySQLAccount struct {
	Username string
	Host     string
}

// Address can be a private tunnel endpoint; TLS.ServerName identifies the actual database server.
type PAMMySQLTarget struct {
	Address string
	TLS     *tls.Config
	Account PAMMySQLAccount
}

type PAMMySQLExecutor struct {
	open func(context.Context, PAMMySQLTarget, PAMMySQLAccount, secret.Material) (*sql.Conn, func(), error)
}

func (account PAMMySQLAccount) valid() bool {
	return account.Username != "" && len(account.Username) <= 255 && account.Host != "" && len(account.Host) <= 255 &&
		!strings.ContainsAny(account.Username+account.Host, "\x00\r\n")
}

func pamMySQLConfig(target PAMMySQLTarget, actor PAMMySQLAccount, material secret.Material) (*mysql.Config, error) {
	host, port, err := net.SplitHostPort(target.Address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host == "" || number < 1 || number > 65535 || !actor.valid() ||
		!target.Account.valid() || material.Kind() != secret.Password {
		return nil, ErrPAMInput
	}
	if target.TLS == nil || target.TLS.InsecureSkipVerify || target.TLS.ServerName == "" {
		return nil, ErrPAMInput
	}
	configuration := mysql.NewConfig()
	configuration.User, configuration.Passwd = actor.Username, material.PasswordValue()
	configuration.Net, configuration.Addr = "tcp", target.Address
	configuration.TLS = target.TLS.Clone()
	configuration.TLS.MinVersion = max(tls.VersionTLS12, configuration.TLS.MinVersion)
	configuration.Timeout, configuration.ReadTimeout, configuration.WriteTimeout = 10*time.Second, 15*time.Second, 15*time.Second
	// The driver escapes literals using the connection's SQL mode, including NO_BACKSLASH_ESCAPES.
	// SET PASSWORD syntax differs from ordinary prepared DML; do not concatenate secrets or account names.
	configuration.InterpolateParams = true
	configuration.AllowFallbackToPlaintext, configuration.MultiStatements, configuration.AllowAllFiles = false, false, false
	return configuration, nil
}

func openPAMMySQL(ctx context.Context, target PAMMySQLTarget, actor PAMMySQLAccount, material secret.Material) (*sql.Conn, func(), error) {
	configuration, err := pamMySQLConfig(target, actor, material)
	if err != nil {
		return nil, nil, err
	}
	connector, err := mysql.NewConnector(configuration)
	if err != nil {
		return nil, nil, err
	}
	database := sql.OpenDB(connector)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(0)
	connection, err := database.Conn(ctx)
	if err != nil {
		database.Close()
		return nil, nil, err
	}
	return connection, func() { connection.Close(); database.Close() }, nil
}

func (executor PAMMySQLExecutor) connection(ctx context.Context, target PAMMySQLTarget, actor PAMMySQLAccount, material secret.Material) (*sql.Conn, func(), error) {
	if _, err := pamMySQLConfig(target, actor, material); err != nil {
		return nil, nil, err
	}
	open := executor.open
	if open == nil {
		open = openPAMMySQL
	}
	return open(ctx, target, actor, material)
}

func pamMySQLFailure(err error, attempted bool) PAMExecutionResult {
	result := PAMExecutionResult{Code: PAMExecutionUnreachable, Attempted: attempted}
	if attempted {
		result.Code = PAMExecutionUnknown
	}
	var databaseError *mysql.MySQLError
	var certificate *tls.CertificateVerificationError
	var hostname x509.HostnameError
	var authority x509.UnknownAuthorityError
	switch {
	case errors.Is(err, ErrPAMInput):
		result.Code = PAMExecutionInvalidInput
	case errors.As(err, &certificate), errors.As(err, &hostname), errors.As(err, &authority):
		result.Code = PAMExecutionIdentity
	case errors.As(err, &databaseError):
		switch databaseError.Number {
		case 1045, 1698:
			result.Code = PAMExecutionAuthentication
			result.ConfirmedUnchanged = attempted
		case 1044, 1142, 1227, 1290:
			result.Code = PAMExecutionDenied
			result.ConfirmedUnchanged = attempted
		case 1819, 1820, 1862, 3638:
			result.Code = PAMExecutionRejected
			result.ConfirmedUnchanged = attempted
		case 1064, 1235:
			result.Code = PAMExecutionUnsupported
			result.ConfirmedUnchanged = attempted
		}
	}
	return result
}

func (executor PAMMySQLExecutor) Verify(ctx context.Context, target PAMMySQLTarget, material secret.Material) PAMExecutionResult {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	connection, close, err := executor.connection(ctx, target, target.Account, material)
	if err != nil {
		return pamMySQLFailure(err, false)
	}
	defer close()
	var principal string
	if err := connection.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&principal); err != nil {
		return pamMySQLFailure(err, false)
	}
	if principal != target.Account.Username+"@"+target.Account.Host {
		return PAMExecutionResult{Code: PAMExecutionIdentity}
	}
	return PAMExecutionResult{Code: PAMExecutionVerified}
}

// Change uses either the account itself or an explicitly authorized recovery account.
// It never reconnects/retries a mutation and never publishes the candidate credential.
func (executor PAMMySQLExecutor) Change(ctx context.Context, target PAMMySQLTarget, actor PAMMySQLAccount,
	current, candidate secret.Material, before PAMBeforeChange) PAMExecutionResult {
	if before == nil || candidate.Kind() != secret.Password || candidate.PasswordValue() == "" ||
		len(candidate.PasswordValue()) > 1024 || strings.ContainsRune(candidate.PasswordValue(), 0) {
		return PAMExecutionResult{Code: PAMExecutionInvalidInput}
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	connection, close, err := executor.connection(ctx, target, actor, current)
	if err != nil {
		return pamMySQLFailure(err, false)
	}
	defer close()
	var version, principal string
	if err := connection.QueryRowContext(ctx, "SELECT VERSION(), CURRENT_USER()").Scan(&version, &principal); err != nil {
		return pamMySQLFailure(err, false)
	}
	if principal != actor.Username+"@"+actor.Host {
		return PAMExecutionResult{Code: PAMExecutionIdentity}
	}
	statement := "SET PASSWORD FOR ?@? = ?"
	arguments := []any{target.Account.Username, target.Account.Host, candidate.PasswordValue()}
	if strings.Contains(strings.ToLower(version), "mariadb") {
		statement = "SET PASSWORD FOR ?@? = PASSWORD(?)"
	} else if strings.HasPrefix(version, "8.") {
		if actor == target.Account {
			statement += " REPLACE ?"
			arguments = append(arguments, current.PasswordValue())
		}
	} else {
		return PAMExecutionResult{Code: PAMExecutionUnsupported}
	}
	if ctx.Err() != nil {
		return PAMExecutionResult{Code: PAMExecutionUnreachable}
	}
	if err := before(ctx); err != nil {
		return PAMExecutionResult{Code: PAMExecutionDenied}
	}
	if ctx.Err() != nil {
		return PAMExecutionResult{Code: PAMExecutionUnreachable}
	}
	// sql.Conn executes against this exact connection; sql.DB.ExecContext would retry ErrBadConn.
	if _, err := connection.ExecContext(ctx, statement, arguments...); err != nil {
		return pamMySQLFailure(err, true)
	}
	return PAMExecutionResult{Code: PAMExecutionChanged, Attempted: true}
}
