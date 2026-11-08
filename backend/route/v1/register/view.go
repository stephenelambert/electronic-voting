package register

import (
	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/certificate"
	"electronic-voting/util/ctxkey"
	"log"
	"net/http"
)

func showAccount() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		account := ctx.Value(ctxkey.Key("account")).(*model.Account)
		modelCert := ctx.Value(ctxkey.Key("certificate")).(*model.Certificate)

		dto := struct {
			ID         string                 `json:"id"`
			Username   string                 `json:"username"`
			PublicKey  string                 `json:"public_key"`
			PrivateKey string                 `json:"private_key"`
			IsAdmin    bool                   `json:"is_admin"`
			AesKey     string                 `json:"aes_key"`
			Certs      []certificate.CertView `json:"certificates,omitempty"`
		}{
			ID:       account.ID,
			Username: account.Username,
			IsAdmin:  account.IsAdmin,
			AesKey:   account.AesKey,
		}

		if account.SigningKey != nil {
			dto.PrivateKey = string(account.SigningKey.PrivateKey)
			dto.PublicKey = account.SigningKey.PublicKey
		}

		if modelCert != nil {
			dto.Certs = []certificate.CertView{
				certificate.ModelCertToView(*modelCert),
			}
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, dto); err != nil {
			log.Printf("error writing json to response: %s", err.Error())
			return
		}
	})
}
