package vote

import (
	"context"
	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/hashtree"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// voteProof is what a client needs to check whether a vote is in an election's published hash
// tree: leaves from the tree, and the nodes that rebuild the root from each of them
type voteProof struct {
	// VoteCount is the number of votes in the tree, which decides its shape
	VoteCount int64
	// Leaves are the vote with the nonce asked about if it's in the tree, and otherwise the votes on
	// either side of where it would be, in nonce order
	Leaves []model.Vote
	// Nodes include every node on each leaf's audit path
	Nodes map[hashtree.NodeID]hashtree.Node
}

// proofToCtx adds the proof for the nonce in the path to the context, once the results of the
// election in the context are published, which is when its hash tree is built. Until then, it's a
// 404 that no cache keeps. Proofs aren't authenticated, so asking for one isn't directly tied to
// the voter's account, but the server can link the two through the authenticated requests around
// it, like the one for the voter's recovery record. Nothing identifying the vote is logged.
func proofToCtx(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		tx := ctx.Value(ctxkey.Key("transaction")).(pgx.Tx)
		election := ctx.Value(ctxkey.Key("election")).(model.Election)

		// the route only matches lowercase hex, but the length is checked too
		nonce := mux.Vars(r)["nonce"]
		if _, err := localcrypto.DecodeNonce(nonce); err != nil {
			writeUncached(w, http.StatusNotFound)
			return
		}

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

		proof := voteProof{
			VoteCount: result.VoteCount,
		}

		leaf := model.Vote{
			ElectionID: election.ID,
			Nonce:      nonce,
		}
		found, err = leaf.FindLeafByElectionAndNonce(ctx, tx)
		if err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}
		if found {
			proof.Leaves = []model.Vote{leaf}
		} else if proof.Leaves, err = model.FindNeighborsOfNonce(ctx, tx, election.ID, nonce); err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}

		ids := []hashtree.NodeID{}
		for _, leaf := range proof.Leaves {
			ids = append(ids, hashtree.AuditPath(leaf.TreePosition, proof.VoteCount)...)
		}
		if proof.Nodes, err = model.FindHashNodes(ctx, tx, election.ID, ids); err != nil {
			writeUncached(w, http.StatusInternalServerError)
			return
		}
		for _, id := range ids {
			if _, ok := proof.Nodes[id]; !ok {
				log.Printf("hash tree of election %s is missing a node", election.ID)
				writeUncached(w, http.StatusInternalServerError)
				return
			}
		}

		ctx = context.WithValue(ctx, ctxkey.Key("vote_proof"), proof)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
