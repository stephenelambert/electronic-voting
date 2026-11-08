package account

import (
	"context"
	"electronic-voting/model"
	"electronic-voting/util/certificate"
	"electronic-voting/util/ctxkey"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// minSetupTokenLength is the shortest setup token AddAdmin accepts. Whoever registers with the
// token first gets a global admin account, so it has to be hard to guess.
const minSetupTokenLength = 16

// AddAdmin makes the account with the given name an admin. If it is not registered, it is created
// or updated with the given setupToken, which can be used to claim the account in registration.
func AddAdmin(ctx context.Context, account_name, setupToken string) (err error) {
	tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)

	if account_name == "" {
		return
	}

	if !model.ValidUsername(account_name) {
		err = fmt.Errorf("admin username %q can't be used, since it starts or ends with whitespace", account_name)
		return
	}

	if setupToken != "" && len(setupToken) < minSetupTokenLength {
		err = fmt.Errorf("admin setup token must be at least %d characters; generate one with: openssl rand -base64 24", minSetupTokenLength)
		return
	}

	acc := &model.Account{
		Username: account_name,
	}

	found, err := acc.FindByUsername(ctx, tx)
	if err != nil {
		err = fmt.Errorf("error finding by username: %v", err)
		return
	}
	if found { // if existing, update admin status, and the setup token if it hasn't registered
		newAdmin := !acc.IsAdmin
		newToken := acc.OpaqueRecord == nil && setupToken != ""
		if !newAdmin && !newToken {
			// already admin-ified, nothing to do
			return
		}

		acc.IsAdmin = true
		if newToken {
			acc.SetSetupToken(setupToken)
		}
		err = acc.Update(ctx, tx)
		if err != nil {
			err = fmt.Errorf("error updating user: %v", err)
			return
		}

		if !newAdmin || acc.SigningKey == nil {
			// no signing key, hasn't registered yet
			return
		}

		_, _, err = certificate.SystemSignAndInsertCert(ctx, model.CertificateGlobalAdminRole, nil, acc.SigningKey.PublicKey, nil)
		if err != nil {
			err = fmt.Errorf("error creating global admin cert: %v", err)
			return
		}

		return
	}
	if setupToken == "" { // not found, but no setup token set
		err = errors.New("cannot create admin without a setup token")
		return
	}

	acc.IsAdmin = true
	acc.SetSetupToken(setupToken)
	err = acc.DbInsert(ctx, tx)
	if err != nil {
		err = fmt.Errorf("error inserting admin into database: %v", err)
		return
	}

	return
}
