package register

import (
	"context"
	"electronic-voting/database"
	lhttp "electronic-voting/http"
	"electronic-voting/localcrypto"
	"electronic-voting/localopaque"
	"electronic-voting/model"
	"electronic-voting/util/certificate"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/dbcrypt"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// startRegistration answers the first message of an OPAQUE registration. Nothing is stored until
// the client sends its registration record to register.
func startRegistration() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		dto := ctx.Value(ctxkey.Key("dto")).(*startRequest)

		if !model.ValidUsername(dto.Username) {
			log.Printf("invalid username in registration (%q)", dto.Username)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// an account the API created and nobody has registered yet goes on like a new one, so it
		// isn't told apart from one
		acc := &model.Account{
			Username: dto.Username,
		}
		found, err := acc.FindByUsername(ctx, tx)
		if err != nil {
			log.Printf("error querying user in registration endpoint: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if found && acc.OpaqueRecord != nil {
			w.WriteHeader(http.StatusConflict)
			return
		}

		response, err := localopaque.RegistrationResponse(dto.Username, dto.RegistrationRequest)
		if errors.Is(err, localopaque.ErrInvalidMessage) {
			log.Printf("invalid OPAQUE registration request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		} else if err != nil {
			log.Printf("error answering OPAQUE registration request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		view := struct {
			RegistrationResponse string `json:"registration_response"`
		}{
			RegistrationResponse: response,
		}
		if err := lhttp.WriteJSON(w, http.StatusOK, view); err != nil {
			log.Printf("error writing json to response: %s", err.Error())
		}
	})
}

func register(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		dto := ctx.Value(ctxkey.Key("dto")).(*request)

		if !model.ValidUsername(dto.Username) {
			log.Printf("invalid username in registration (%q)", dto.Username)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		record, err := localopaque.ParseRecord(dto.RegistrationRecord)
		if err != nil {
			log.Printf("invalid OPAQUE registration record: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// check and normalize public key. The account signs requests with it, so it must be a key
		// browsers will check those signatures with
		publicKey, _, err := localcrypto.ParseAccountPublicKey(dto.PublicKey)
		if err != nil {
			log.Printf("invalid public key in registration (%s): %v", dto.PublicKey, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		account := &model.Account{
			Username:     dto.Username,
			OpaqueRecord: record,
			AesKey:       dto.AesKey,
		}

		isAdminSetup := false

		acc := &model.Account{
			Username: dto.Username,
		}
		found, err := acc.FindByUsername(ctx, tx)
		if err != nil {
			log.Printf("error querying user in registration endpoint: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if found && acc.OpaqueRecord == nil { // account created by the API but not registered
			log.Print("found unregistered user in registration")
			// For now, a registration token is only for global admins
			if dto.RegistrationToken == nil || !acc.SetupTokenMatches(*dto.RegistrationToken) {
				log.Print("invalid setup token in registration")
				// return conflict to conceal any potential leak of "unclaimed" account
				w.WriteHeader(http.StatusConflict)
				return
			}

			acc.OpaqueRecord = account.OpaqueRecord
			acc.AesKey = account.AesKey
			claimed, err := acc.Claim(ctx, tx)
			if err != nil {
				log.Printf("error claiming account for registration: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if !claimed {
				// a concurrent registration claimed it first, like from a form submitted twice. It's
				// taken now, and going on would give the account a second signing key
				log.Print("unregistered user was claimed by a concurrent registration")
				w.WriteHeader(http.StatusConflict)
				return
			}
			account = acc

			isAdminSetup = account.IsAdmin
		} else if found {
			w.WriteHeader(http.StatusConflict)
			return
		} else {
			err := account.DbInsert(ctx, tx)
			if err != nil && database.ErrorIsDuplicateKeyValue(err) {
				w.WriteHeader(http.StatusConflict)
				return
			} else if err != nil {
				log.Printf("error inserting account: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// insert the signing key
		signingKey := &model.SigningKey{
			PrivateKey:        dbcrypt.EncryptedString(dto.PrivateKey),
			PublicKey:         publicKey,
			OwnerType:         model.KeyAccountOwner,
			OwnerID:           &account.ID,
			CreationTimestamp: time.Now().Unix(),
		}

		err = signingKey.DbInsert(ctx, tx)
		if err != nil && database.ErrorIsDuplicateKeyValue(err) {
			log.Print("public key in registration already in use")
			w.WriteHeader(http.StatusConflict)
			return
		} else if err != nil {
			log.Printf("error inserting signing key for new account: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		account.SigningKey = &model.SigningKeyLite{
			ID:         signingKey.ID,
			PublicKey:  publicKey,
			PrivateKey: signingKey.PrivateKey,
		}

		var modelCert *model.Certificate

		// create the certificate for admins
		if isAdminSetup {
			log.Print("creating global admin cert...")
			var status int
			modelCert, status, err = certificate.SystemSignAndInsertCert(ctx, model.CertificateGlobalAdminRole, nil, signingKey.PublicKey, nil)
			if err != nil {
				log.Printf("error creating global admin cert: %v", err)
				w.WriteHeader(status)
				return
			}
		}

		ctx = context.WithValue(ctx, ctxkey.Key("account"), account)
		ctx = context.WithValue(ctx, ctxkey.Key("certificate"), modelCert)

		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
