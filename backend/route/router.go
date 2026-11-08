package route

import (
	lhttp "electronic-voting/http"
	v1 "electronic-voting/route/v1"

	"github.com/gorilla/mux"
)

// Router returns a root router for the API
func Router() (router *mux.Router) {
	router = mux.NewRouter()
	api_router := router.PathPrefix("/api").Subrouter()
	// a panic in a handler skips TxToCtx's commit, so the deferred rollback runs, and the response
	// TxToCtx is holding is never sent. Go's HTTP server then logs the panic and closes the
	// connection
	api_router.Use(lhttp.TxToCtx)

	v1.Router(api_router)

	return
}
