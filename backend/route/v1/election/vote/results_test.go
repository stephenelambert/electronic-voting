package vote

import (
	"electronic-voting/localcrypto"
	"encoding/base64"
	"testing"
)

const testResultsElectionID = "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"

// testResults returns a valid request to publish results for three votes
func testResults() resultsRequest {
	return resultsRequest{
		ElectionID: testResultsElectionID,
		VoteCount:  3,
		RootHash:   base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		Tally:      `{"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d":2,"a1b2c3d4-e5f6-4789-8abc-def012345678":1}`,
	}
}

func TestResultsBodyIsExact(t *testing.T) {
	body, err := localcrypto.CanonicalJSON(testResults())
	if err != nil {
		t.Fatalf("error encoding results: %v", err)
	}

	// admins' clients sign this encoding, so the frontend's tests check it too
	want := `{"election_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a","vote_count":3,"root_hash":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","tally":"{\"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d\":2,\"a1b2c3d4-e5f6-4789-8abc-def012345678\":1}"}`
	if string(body) != want {
		t.Errorf("results body is\n%s\nwant\n%s", body, want)
	}
}

func TestValidateResultsAcceptsValidResults(t *testing.T) {
	req := testResults()

	if reason := validateResults(&req, testResultsElectionID); reason != "" {
		t.Errorf("valid results were rejected: %s", reason)
	}
}

func TestValidateResultsRejectsInvalidResults(t *testing.T) {
	// bodies in other encodings are rejected before this, like every signed request's (see
	// CanonicalDtoToCtx)
	cases := map[string]func(req *resultsRequest){
		"other election": func(req *resultsRequest) {
			req.ElectionID = "6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d"
		},
		"root hash not base64": func(req *resultsRequest) {
			req.RootHash = "not base64!"
		},
		"short root hash": func(req *resultsRequest) {
			req.RootHash = base64.StdEncoding.EncodeToString(make([]byte, 31))
		},
		"tally not canonical": func(req *resultsRequest) {
			req.Tally = `{"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d": 3}`
		},
		"tally missing votes": func(req *resultsRequest) {
			req.Tally = `{"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d":2}`
		},
		"negative vote count": func(req *resultsRequest) {
			req.VoteCount = -1
			req.Tally = "{}"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			req := testResults()
			change(&req)
			if reason := validateResults(&req, testResultsElectionID); reason == "" {
				t.Errorf("results %+v were accepted", req)
			}
		})
	}
}
