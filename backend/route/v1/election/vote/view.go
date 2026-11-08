package vote

import (
	lhttp "electronic-voting/http"
	"electronic-voting/model"
	"electronic-voting/util/ctxkey"
	"electronic-voting/util/hashtree"
	"electronic-voting/util/signedrequest"
	"electronic-voting/util/votecounts"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
)

// blindSignatureView is the election key's signature on a voter's blinded vote, which is base64
type blindSignatureView struct {
	BlindSignature string `json:"blind_signature"`
}

// showRecoveryRecord writes the recovery record in the context to the HTTP response with the given
// status. The record is the signed request that uploaded it, so the client can check it made the
// request before decrypting the record in its body.
func showRecoveryRecord(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		record := ctx.Value(ctxkey.Key("recovery_record")).(model.VoteRecoveryRecord)

		if err := lhttp.WriteJSON(w, status, signedrequest.ToView(record.SignedRequest)); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// showBlindSignature writes the signature of the blind signed vote in the context to the HTTP
// response with the given status
func showBlindSignature(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		vote := ctx.Value(ctxkey.Key("blind_signed_vote")).(model.BlindSignedVote)

		if err := lhttp.WriteJSON(w, status, blindSignatureView{BlindSignature: vote.BlindSignature}); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// showStatus writes only the given status to the HTTP response
func showStatus(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	})
}

// publishedVoteView is a published vote. Vote is the vote JSON exactly as signed, kept as a string
// so its bytes survive
type publishedVoteView struct {
	Nonce     string `json:"nonce"`
	Vote      string `json:"vote"`
	Signature string `json:"signature"`
}

func toPublishedVoteView(vote model.Vote) publishedVoteView {
	return publishedVoteView{
		Nonce:     vote.Nonce,
		Vote:      vote.Raw,
		Signature: vote.Signature,
	}
}

// tallyView is how many of the published votes are for a candidate, who may not be on the ballot
type tallyView struct {
	CandidateID string `json:"candidate_id"`
	Votes       uint64 `json:"votes"`
}

// toTallyViews lists the counts for the election's candidates in ballot order, including those with
// no votes, then the counts for any other candidate IDs that votes named, in ID order
func toTallyViews(election model.Election, counts votecounts.Counts) []tallyView {
	views := make([]tallyView, 0, len(election.Candidates))
	onBallot := make(map[string]bool, len(election.Candidates))
	for _, candidate := range election.Candidates {
		onBallot[candidate.ID] = true
		views = append(views, tallyView{
			CandidateID: candidate.ID,
			Votes:       counts[candidate.ID],
		})
	}

	others := []string{}
	for candidateID, count := range counts {
		if !onBallot[candidateID] && count != 0 {
			others = append(others, candidateID)
		}
	}
	slices.Sort(others)
	for _, candidateID := range others {
		views = append(views, tallyView{
			CandidateID: candidateID,
			Votes:       counts[candidateID],
		})
	}

	return views
}

// summaryView summarizes the votes in an election: how many have been cast, whether every vote is
// published, which only happens once the election closes, and from then, the tally
type summaryView struct {
	VotesCast int64       `json:"votes_cast"`
	Complete  bool        `json:"complete"`
	Tally     []tallyView `json:"tally"`
}

// showSummary writes the summary of the votes in the election in the context to the HTTP response
func showSummary() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		election := ctx.Value(ctxkey.Key("election")).(model.Election)
		summary := ctx.Value(ctxkey.Key("vote_summary")).(voteSummary)

		view := summaryView{
			VotesCast: summary.VotesCast,
			Complete:  summary.Final,
			Tally:     []tallyView{},
		}
		if summary.Final {
			view.Tally = toTallyViews(election, summary.Tally)
		}

		w.Header().Set("Cache-Control", summaryCacheControl)
		if err := lhttp.WriteJSON(w, http.StatusOK, view); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// showPublishedVotes writes the published votes in the context to the HTTP response as JSON Lines,
// one vote per line in nonce order. They never change once they're published, so the same URL always
// gets the same bytes and can be cached forever.
func showPublishedVotes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		election := ctx.Value(ctxkey.Key("election")).(model.Election)
		votes := ctx.Value(ctxkey.Key("published_votes")).([]model.Vote)

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", immutableCacheControl)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="votes-%s.jsonl"`, election.ID))
		w.WriteHeader(http.StatusOK)

		for _, vote := range votes {
			// a struct of strings always encodes
			line, _ := json.Marshal(toPublishedVoteView(vote))
			if _, err := w.Write(append(line, '\n')); err != nil {
				log.Printf("error writing published votes to response: %v", err)
				return
			}
		}
	})
}

// blindSignatureRequestView is a voter's signed request for a blind signature, along with the admin's
// signed request that authorized the voter's certificate, so auditors can check that the voter was
// authorized
type blindSignatureRequestView struct {
	SignedRequest signedrequest.View `json:"signed_request"`
	Authorization signedrequest.View `json:"authorization"`
}

// showBlindSignatureRequests writes the signed requests of the blind signed votes in the context to
// the HTTP response as a JSON array. Unlike the votes, they aren't cached forever: blind signatures
// stop by this server's clock rather than the database's, so a server whose clock is behind can still
// sign one after the counter is final, though no vote can be cast with it.
func showBlindSignatureRequests() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		votes := ctx.Value(ctxkey.Key("blind_signed_votes")).(model.BlindSignedVotes)
		views := make([]blindSignatureRequestView, len(votes))
		for i, vote := range votes {
			views[i] = blindSignatureRequestView{
				SignedRequest: signedrequest.ToView(vote.SignedRequest),
				Authorization: signedrequest.ToView(vote.Authorization),
			}
		}

		if err := lhttp.WriteJSON(w, http.StatusOK, views); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}

// resultsView is an election's published results: the admin's signed request publishing them, which
// clients check before trusting them, and when they were published
type resultsView struct {
	SignedRequest    signedrequest.View `json:"signed_request"`
	CreatedTimestamp int64              `json:"created_timestamp"`
}

// writeResults writes the published results in the context to the HTTP response with the given
// status
func writeResults(w http.ResponseWriter, r *http.Request, status int) {
	result := r.Context().Value(ctxkey.Key("election_result")).(model.ElectionResult)
	view := resultsView{
		SignedRequest:    signedrequest.ToView(result.SignedRequest),
		CreatedTimestamp: result.CreatedTimestamp,
	}

	if err := lhttp.WriteJSON(w, status, view); err != nil {
		log.Printf("error writing json to response: %v", err)
		return
	}
}

// showResults writes the published results in the context to the HTTP response with the given
// status, for the admin who published them
func showResults(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeResults(w, r, status)
	})
}

// showPublishedResults writes the published results in the context to the HTTP response, for anyone
// to read. They never change once they're published, so they can be cached forever.
func showPublishedResults() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", immutableCacheControl)
		writeResults(w, r, http.StatusOK)
	})
}

// treeNodeView is a node of an election's hash tree: the votes under it, their counts, exactly as
// they're hashed, and its hash (base64)
type treeNodeView struct {
	FirstLeaf int64  `json:"first_leaf"`
	LeafCount int64  `json:"leaf_count"`
	Counts    string `json:"counts"`
	Hash      string `json:"hash"`
}

// proofLeafView is a published vote in an election's hash tree, with its position in the tree and its
// path: the sibling of each node from the vote's leaf up to the root, bottom-up
type proofLeafView struct {
	Position  int64          `json:"position"`
	Nonce     string         `json:"nonce"`
	Vote      string         `json:"vote"`
	Signature string         `json:"signature"`
	Path      []treeNodeView `json:"path"`
}

// proofView is the proof for a nonce: the vote with the nonce if it's in the tree, and otherwise the
// votes on either side of where it would be. Those are next to each other in the tree, so they show
// no vote lies between them.
type proofView struct {
	Leaves []proofLeafView `json:"leaves"`
}

func toProofView(proof voteProof) proofView {
	view := proofView{
		Leaves: make([]proofLeafView, len(proof.Leaves)),
	}
	for i, leaf := range proof.Leaves {
		ids := hashtree.AuditPath(leaf.TreePosition, proof.VoteCount)
		path := make([]treeNodeView, len(ids))
		for j, id := range ids {
			node := proof.Nodes[id]
			path[j] = treeNodeView{
				FirstLeaf: node.FirstLeaf,
				LeafCount: node.LeafCount,
				Counts:    node.Counts,
				Hash:      base64.StdEncoding.EncodeToString(node.Hash[:]),
			}
		}

		view.Leaves[i] = proofLeafView{
			Position:  leaf.TreePosition,
			Nonce:     leaf.Nonce,
			Vote:      leaf.Raw,
			Signature: leaf.Signature,
			Path:      path,
		}
	}

	return view
}

// showProof writes the proof in the context to the HTTP response. An election's hash tree never
// changes once it's built, so neither do its proofs, and they can be cached forever.
func showProof() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		proof := ctx.Value(ctxkey.Key("vote_proof")).(voteProof)

		w.Header().Set("Cache-Control", immutableCacheControl)
		if err := lhttp.WriteJSON(w, http.StatusOK, toProofView(proof)); err != nil {
			log.Printf("error writing json to response: %v", err)
			return
		}
	})
}
