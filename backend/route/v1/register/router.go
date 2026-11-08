package register

import (
	"net/http"

	lhttp "electronic-voting/http"

	"github.com/gorilla/mux"
)

func Router(r *mux.Router) {
	sub := r.PathPrefix("/register").Subrouter()
	sub.Methods(http.MethodPost).Path("/start").
		Handler(lhttp.BodyToCtx(lhttp.DtoToCtx[startRequest]("dto", startRegistration())))
	sub.Methods(http.MethodPost).Path("").
		Handler(lhttp.BodyToCtx(lhttp.DtoToCtx[request]("dto", register(showAccount()))))
}
