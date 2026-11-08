package vote

import (
	"context"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/votecounts"
	"fmt"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

const (
	// immutableCacheControl is for the published votes, which never change once they're served
	immutableCacheControl = "public, max-age=31536000, immutable"

	// summaryCacheControl is for the summary, which changes with every vote until the election closes
	summaryCacheControl = "public, max-age=10"
)

// writeUncached writes only the given status, for a response no cache should keep, like a 404 for
// votes that are published later
func writeUncached(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}

// freezeIfClosed freezes the election's counter if the election has closed by the database's clock,
// then returns the counter. Until the close, freezing does nothing. Once the election has closed, it
// waits for any vote still being cast, and casting checks the flag after counting, so once the
// counter is final, every vote is in and the votes can be published.
func freezeIfClosed(ctx context.Context, tx pgx.Tx, electionID string) (counter model.ElectionVoteCounter, err error) {
	counter = model.ElectionVoteCounter{
		ElectionID: electionID,
	}
	if _, err = counter.Freeze(ctx, tx); err != nil {
		return
	}

	// read after freezing, so it includes a freeze by this request or by one it waited for
	found, err := counter.FindByElection(ctx, tx)
	if err == nil && !found {
		err = fmt.Errorf("election %s has no vote counter", electionID)
		log.Print(err)
	}

	return
}

// voteSummary is what summarize works out about the votes in an election
type voteSummary struct {
	VotesCast int64
	Final     bool
	// Tally is only counted once the counter is final, since a tally that changed with every vote
	// would show how each vote was cast as it arrived
	Tally votecounts.Counts
}

// summarize adds a summary of the votes in the election in the context to the context. Once the
// election has closed by the database's clock, the first request freezes its counter, which publishes
// its votes.
func summarize(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)

		counter, err := freezeIfClosed(ctx, tx, election.ID)
		if err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}

		summary := voteSummary{
			VotesCast: counter.VotesCast,
			Final:     counter.Final,
			Tally:     votecounts.Counts{},
		}
		if counter.Final {
			if summary.Tally, err = model.CountVotesByCandidate(ctx, tx, election.ID); err != nil {
				writeUncached(w, http.StatusInternalServerError)
				return
			}
		}

		ctx = context.WithValue(ctx, ctxkey.Key("vote_summary"), summary)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// publishedToCtx adds every vote in the election in the context to the context, in nonce order, once
// the election's counter is final. Until then the votes aren't published, and it's a 404. Like the
// summary, the first request after the election closes freezes its counter.
func publishedToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)

		counter, err := freezeIfClosed(ctx, tx, election.ID)
		if err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}
		if !counter.Final {
			writeUncached(w, http.StatusNotFound)
			return
		}

		votes, err := model.ListVotesByNonce(ctx, tx, election.ID)
		if err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("published_votes"), votes)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

// blindSignatureRequestsToCtx adds every vote signed blind in the election in the context to the
// context, each with the voter's signed request for the signature and the admin's signed request that
// authorized the voter, once the election's counter is final. The requests are published with the
// votes, so until then it's a 404, and nobody can see who has voted while the election is open. Like
// the votes, the first request after the election closes freezes its counter.
func blindSignatureRequestsToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)

		counter, err := freezeIfClosed(ctx, tx, election.ID)
		if err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}
		if !counter.Final {
			writeUncached(w, http.StatusNotFound)
			return
		}

		votes := model.BlindSignedVotes{}
		if err = votes.FindByElection(ctx, tx, election.ID); err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("blind_signed_votes"), votes)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
