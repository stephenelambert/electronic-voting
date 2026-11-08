package jurisdiction

import (
	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/signedrequest"
	"log"
	"net/http"
)

// jurisdictionView is a jurisdiction along with the admin's signed request that created it, so
// clients can check who created it
type jurisdictionView struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Info             string             `json:"info"`
	CreatedTimestamp int64              `json:"created_timestamp"`
	SignedRequest    signedrequest.View `json:"signed_request"`
}

// jurisdictionSummaryView is a jurisdiction as it appears in lists
type jurisdictionSummaryView struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Info             string `json:"info"`
	CreatedTimestamp int64  `json:"created_timestamp"`
}

func toView(jurisdiction model.Jurisdiction) jurisdictionView {
	return jurisdictionView{
		ID:               jurisdiction.ID,
		Name:             jurisdiction.Name,
		Info:             jurisdiction.Info,
		CreatedTimestamp: jurisdiction.CreatedTimestamp,
		SignedRequest:    signedrequest.ToView(jurisdiction.SignedRequest),
	}
}

func showJurisdiction() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		jurisdiction := ctx.Value(ctxkey.Key("jurisdiction")).(model.Jurisdiction)

		if err := lhttp.WriteJSON(w, http.StatusOK, toView(jurisdiction)); err != nil {
			log.Printf("error writing json to response: %s", err.Error())
			return
		}
	})
}

// showJurisdictions takes the jurisdictions in the context and writes them to the HTTP response
// as a JSON array of summaries.
func showJurisdictions() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		jurisdictions := ctx.Value(ctxkey.Key("jurisdictions")).(model.Jurisdictions)
		views := make([]jurisdictionSummaryView, len(jurisdictions))
		for i, jurisdiction := range jurisdictions {
			views[i] = jurisdictionSummaryView{
				ID:               jurisdiction.ID,
				Name:             jurisdiction.Name,
				Info:             jurisdiction.Info,
				CreatedTimestamp: jurisdiction.CreatedTimestamp,
			}
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, views); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}
