package login

import (
	"net/http"

	lhttp "electronic-voting/http"

	"github.com/gorilla/mux"
)

func Router(r *mux.Router) {
	sub := r.PathPrefix("/login").Subrouter()
	sub.Methods(http.MethodPost).Path("/start").
		Handler(lhttp.BodyToCtx(lhttp.DtoToCtx[startRequest]("dto", startLogin())))
	sub.Methods(http.MethodPut).Path("").
		Handler(lhttp.BodyToCtx(lhttp.DtoToCtx[request]("dto", login(showAccount()))))
}
