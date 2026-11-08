package vote

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"electronic-voting/model"
	"electronic-voting/util/votecounts"
)

func TestToTallyViewsListsBallotThenOtherCandidates(t *testing.T) {
	election := model.Election{
		Candidates: []model.Candidate{
			{ID: "6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d"},
			{ID: "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"},
		},
	}
	counts := votecounts.Counts{
		"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a": 3,
		// candidates that aren't on the ballot
		"f1d2c3b4-a5e6-4789-8abc-def012345678": 2,
		"a1b2c3d4-e5f6-4789-8abc-def012345678": 1,
		"b1b2c3d4-e5f6-4789-8abc-def012345678": 0,
	}

	got := toTallyViews(election, counts)

	// ballot order with zeros, then other IDs that have votes, in ID order
	want := []tallyView{
		{CandidateID: "6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d", Votes: 0},
		{CandidateID: "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a", Votes: 3},
		{CandidateID: "a1b2c3d4-e5f6-4789-8abc-def012345678", Votes: 1},
		{CandidateID: "f1d2c3b4-a5e6-4789-8abc-def012345678", Votes: 2},
	}
	if !slices.Equal(got, want) {
		t.Errorf("tally is %v, want %v", got, want)
	}
}

func TestPublishedVoteLineIsExact(t *testing.T) {
	vote := model.Vote{
		Nonce:     strings.Repeat("ab", 32),
		Raw:       `{"version":1,"election_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a","candidate_id":"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d"}`,
		Signature: "c2ln+/==",
	}

	line, err := json.Marshal(toPublishedVoteView(vote))
	if err != nil {
		t.Fatalf("error encoding published vote: %v", err)
	}

	// clients and auditors read the vote's exact bytes back out of the line, so its encoding is fixed
	want := `{"nonce":"` + vote.Nonce + `","vote":"{\"version\":1,\"election_id\":\"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a\",\"candidate_id\":\"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d\"}","signature":"c2ln+/=="}`
	if string(line) != want {
		t.Errorf("published vote line is\n%s\nwant\n%s", line, want)
	}
}
