package election

import (
	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/signedrequest"
	"log"
	"net/http"
)

type candidateView struct {
	ID          string `json:"id"`
	Position    int    `json:"position"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type electionView struct {
	ID               string          `json:"id"`
	JurisdictionID   string          `json:"jurisdiction_id"`
	Title            string          `json:"title"`
	Description      string          `json:"description"`
	TimeOpen         int64           `json:"time_open"`
	TimeClose        int64           `json:"time_close"`
	CreatedTimestamp int64           `json:"created_timestamp"`
	PublicKey        string          `json:"public_key"`
	Candidates       []candidateView `json:"candidates"`
	// SignedRequest is the admin's signed request that created the election, which certifies its key
	SignedRequest signedrequest.View `json:"signed_request"`
}

// electionSummaryView is an election as it appears in lists
type electionSummaryView struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	TimeOpen  int64  `json:"time_open"`
	TimeClose int64  `json:"time_close"`
}

// keyView is an election key that a request to create an election can claim
type keyView struct {
	PublicKey string `json:"public_key"`
}

func toView(election model.Election) electionView {
	view := electionView{
		ID:               election.ID,
		JurisdictionID:   election.JurisdictionID,
		Title:            election.Title,
		Description:      election.Description,
		TimeOpen:         election.TimeOpen,
		TimeClose:        election.TimeClose,
		CreatedTimestamp: election.CreatedTimestamp,
		PublicKey:        election.PublicKey,
		Candidates:       make([]candidateView, len(election.Candidates)),
		SignedRequest:    signedrequest.ToView(election.SignedRequest),
	}
	for i, candidate := range election.Candidates {
		view.Candidates[i] = candidateView{
			ID:          candidate.ID,
			Position:    candidate.Position,
			Name:        candidate.Name,
			Description: candidate.Description,
		}
	}

	return view
}

// showElection writes the election in the context to the HTTP response with the given status.
func showElection(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		election := ctx.Value(ctxkey.Key("election")).(model.Election)

		if err := lhttp.WriteJSON(w, status, toView(election)); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// showKey writes the public key of the election key in the context to the HTTP response with the
// given status.
func showKey(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		signingKey := ctx.Value(ctxkey.Key("signing_key")).(model.SigningKey)

		if err := lhttp.WriteJSON(w, status, keyView{PublicKey: signingKey.PublicKey}); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// showElections writes the elections in the context to the HTTP response as a JSON array of
// summaries.
func showElections() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		elections := ctx.Value(ctxkey.Key("elections")).(model.Elections)
		views := make([]electionSummaryView, len(elections))
		for i, election := range elections {
			views[i] = electionSummaryView{
				ID:        election.ID,
				Title:     election.Title,
				TimeOpen:  election.TimeOpen,
				TimeClose: election.TimeClose,
			}
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, views); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}
