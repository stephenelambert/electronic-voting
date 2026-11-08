package vote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/hashtree"
	"electronic-voting/util/votecounts"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// validateResults returns why a request to publish the election's results is invalid, or "" if it
// is valid. The route has already checked that the body is in canonical form. Whether the results
// match the election's votes is only checked once its hash tree is built.
func validateResults(req *resultsRequest, electionID string) string {
	if req.ElectionID != electionID {
		return "results are for a different election"
	}

	rootHash, err := localcrypto.DecodeBase64(req.RootHash)
	if err != nil || len(rootHash) != sha256.Size {
		return "root hash is not a base64 sha-256 hash"
	}

	tally, err := votecounts.Decode(req.Tally)
	if err != nil {
		return "tally is not in canonical form"
	}
	if req.VoteCount < 0 || tally.Total() != uint64(req.VoteCount) {
		return "tally doesn't count every vote"
	}

	return ""
}

// buildTree builds the hash tree of the election's votes, which must be final, and returns its root.
// votesCast is the election's final count of votes cast, which the votes found have to match.
func buildTree(ctx context.Context, tx pgx.Tx, electionID string, votesCast int64) (root hashtree.Node, err error) {
	votes, err := model.ListVotesByNonce(ctx, tx, electionID)
	if err != nil {
		return
	}
	if int64(len(votes)) != votesCast {
		err = fmt.Errorf("election %s has %d votes, but its counter counted %d", electionID, len(votes), votesCast)
		log.Print(err)
		return
	}

	leaves := make([]hashtree.Leaf, len(votes))
	for i, vote := range votes {
		leaf := hashtree.Leaf{
			Vote:        vote.Raw,
			CandidateID: vote.CandidateID,
		}
		if leaf.Nonce, err = localcrypto.DecodeNonce(vote.Nonce); err != nil {
			log.Printf("invalid stored vote nonce: %v", err)
			return
		}
		if leaf.Signature, err = localcrypto.DecodeBase64(vote.Signature); err != nil {
			log.Printf("invalid stored vote signature: %v", err)
			return
		}

		// the database sets the positions, so it has to sort nonces in byte order, like the tree
		if i > 0 && bytes.Compare(leaves[i-1].Nonce, leaf.Nonce) >= 0 {
			err = fmt.Errorf("votes in election %s aren't in nonce byte order", electionID)
			log.Print(err)
			return
		}

		leaves[i] = leaf
	}

	positioned, err := model.SetTreePositions(ctx, tx, electionID)
	if err != nil {
		return
	}
	if positioned != votesCast {
		err = fmt.Errorf("positioned %d votes in election %s, but it has %d", positioned, electionID, votesCast)
		log.Print(err)
		return
	}

	var nodes []hashtree.Node
	root, nodes = hashtree.Build(leaves)
	err = model.InsertHashNodes(ctx, tx, electionID, nodes)

	return
}

// publishResults publishes the results in the request for the election in the context, with the
// authenticated admin's signed request, and builds the election's hash tree, which proofs are
// served from. The results must match the tree, so results an admin's client worked out from the
// published votes also show the tree matches them. Results can't be replaced, but a client that lost
// the response can send the same body again: alreadyPublished is served for it instead of published.
func publishResults(published, alreadyPublished http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)
		signedRequest := ctx.Value(ctxkey.Key("signed_request")).(model.SignedRequest)
		req := ctx.Value(ctxkey.Key("dto")).(*resultsRequest)

		if reason := validateResults(req, election.ID); reason != "" {
			log.Printf("invalid request to publish results: %s", reason)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// held until the request ends, so requests to publish the election's results run one at a
		// time and its tree is only built once
		counter := model.ElectionVoteCounter{
			ElectionID: election.ID,
		}
		found, err := counter.Lock(ctx, tx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		} else if !found {
			log.Printf("election %s has no vote counter", election.ID)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// the counter isn't frozen here, since freezing would hold its row until the tree was built,
		// and every request for the summary or the votes would wait for it. The admin's client
		// freezes it by downloading the votes
		if !counter.Final {
			log.Printf("votes in election %s aren't final", election.ID)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		existing := model.ElectionResult{
			ElectionID: election.ID,
		}
		found, err = existing.FindByElection(ctx, tx)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if found {
			if existing.SignedRequest.Body != signedRequest.Body {
				log.Printf("different results were already published for election %s", election.ID)
				w.WriteHeader(http.StatusConflict)
				return
			}

			ctx = context.WithValue(ctx, ctxkey.Key("election_result"), existing)
			alreadyPublished.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		root, err := buildTree(ctx, tx, election.ID, counter.VotesCast)
		if err != nil {
			log.Printf("error building hash tree: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rootHash := base64.StdEncoding.EncodeToString(root.Hash[:])
		if req.VoteCount != counter.VotesCast || req.RootHash != rootHash || req.Tally != root.Counts {
			// the 400 rolls the tree back, and it's built the same way next time
			log.Printf("results for election %s don't match its hash tree: %d votes with root %s and tally %s were sent, but the tree has %d with root %s and tally %s",
				election.ID, req.VoteCount, req.RootHash, req.Tally, counter.VotesCast, rootHash, root.Counts)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result := model.ElectionResult{
			ElectionID:       election.ID,
			VoteCount:        counter.VotesCast,
			SignedRequest:    signedRequest,
			CreatedTimestamp: time.Now().Unix(),
		}
		if err = result.DBInsert(ctx, tx); err != nil {
			log.Printf("error inserting election result: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("election_result"), result)
		published.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resultsToCtx adds the published results of the election in the context to the context. Until
// they're published, it's a 404 that no cache keeps.
func resultsToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)

		result := model.ElectionResult{
			ElectionID: election.ID,
		}
		found, err := result.FindByElection(ctx, tx)
		if err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}
		if !found {
			writeUncached(w, http.StatusNotFound)
			return
		}

		ctx = context.WithValue(ctx, ctxkey.Key("election_result"), result)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
