package localcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

const (
	testElectionID  = "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"
	testCandidateID = "6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d"
)

// testVote returns a vote in the one accepted encoding
func testVote(candidateID string) string {
	return `{"version":1,"election_id":"` + testElectionID + `","candidate_id":"` + candidateID + `"}`
}

// testElectionKeys generates an election key pair the way the API does
func testElectionKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()

	privateKeyPEM, publicKeyPEM, err := GenerateElectionKey()
	if err != nil {
		t.Fatalf("error generating election key: %v", err)
	}
	privateKey, err := ParseElectionPrivateKey(privateKeyPEM)
	if err != nil {
		t.Fatalf("error parsing election private key: %v", err)
	}
	publicKey, err := ParseElectionPublicKey(publicKeyPEM)
	if err != nil {
		t.Fatalf("error parsing election public key: %v", err)
	}

	return privateKey, publicKey
}

func TestParseVoteAcceptsCanonicalVote(t *testing.T) {
	vote, err := ParseVote(testVote(testCandidateID))
	if err != nil {
		t.Fatalf("canonical vote was rejected: %v", err)
	}

	want := VoteContent{Version: VoteVersion, ElectionID: testElectionID, CandidateID: testCandidateID}
	if vote != want {
		t.Errorf("parsed vote is %+v, want %+v", vote, want)
	}
}

func TestParseVoteRejectsOtherEncodings(t *testing.T) {
	canonical := testVote(testCandidateID)

	cases := map[string]string{
		"whitespace":     strings.Replace(canonical, ",", ", ", 1),
		"field order":    `{"election_id":"` + testElectionID + `","version":1,"candidate_id":"` + testCandidateID + `"}`,
		"extra field":    strings.TrimSuffix(canonical, "}") + `,"write_in":"someone"}`,
		"missing field":  `{"version":1,"election_id":"` + testElectionID + `"}`,
		"repeated field": strings.Replace(canonical, `"candidate_id"`, `"candidate_id":"other","candidate_id"`, 1),
		"key case":       strings.Replace(canonical, `"version"`, `"Version"`, 1),
		"escape":         strings.Replace(canonical, `"`+testElectionID, `"\u0030`+testElectionID[1:], 1),
		"uppercase id":   testVote(strings.ToUpper(testCandidateID)),
		"other version":  strings.Replace(canonical, `"version":1`, `"version":2`, 1),
		"trailing space": canonical + " ",
		"not json":       "vote",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseVote(raw); err == nil {
				t.Errorf("vote %q was accepted", raw)
			}
		})
	}
}

func TestDecodeNonce(t *testing.T) {
	nonce := make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("error generating nonce: %v", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	decoded, err := DecodeNonce(nonceHex)
	if err != nil {
		t.Fatalf("lowercase hex nonce was rejected: %v", err)
	}
	if hex.EncodeToString(decoded) != nonceHex {
		t.Errorf("decoded nonce doesn't match")
	}

	invalid := map[string]string{
		"uppercase": strings.ToUpper(nonceHex),
		"too short": nonceHex[2:],
		"not hex":   strings.Repeat("g", 2*NonceBytes),
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeNonce(value); err == nil {
				t.Errorf("nonce %q was accepted", value)
			}
		})
	}
}

func TestDecodeBase64RejectsOtherEncodings(t *testing.T) {
	if _, err := DecodeBase64("QUJD"); err != nil {
		t.Fatalf("canonical base64 was rejected: %v", err)
	}

	invalid := map[string]string{
		// both decode to the same bytes as a canonical encoding
		"newline":              "QU\nJD",
		"nonzero padding bits": "QR==",
		"not base64":           "QUJD!",
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBase64(value); err == nil {
				t.Errorf("base64 %q was accepted", value)
			}
		})
	}
}

func TestBlindSignAndVerifyVote(t *testing.T) {
	privateKey, publicKey := testElectionKeys(t)
	vote := testVote(testCandidateID)

	// blind and unblind as the voter's client does
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, publicKey)
	if err != nil {
		t.Fatalf("error creating client: %v", err)
	}
	prepared, err := client.Prepare(rand.Reader, []byte(vote))
	if err != nil {
		t.Fatalf("error preparing vote: %v", err)
	}
	blinded, state, err := client.Blind(rand.Reader, prepared)
	if err != nil {
		t.Fatalf("error blinding vote: %v", err)
	}

	blindSignature, err := BlindSign(privateKey, blinded)
	if err != nil {
		t.Fatalf("error signing blinded vote: %v", err)
	}

	signature, err := client.Finalize(state, blindSignature)
	if err != nil {
		t.Fatalf("error unblinding signature: %v", err)
	}

	// the prepared message is what clients split into the nonce and the vote they cast
	nonce, preparedVote := prepared[:NonceBytes], prepared[NonceBytes:]
	if string(preparedVote) != vote {
		t.Fatalf("prepared message is not the nonce followed by the vote")
	}

	if err = VerifyVote(publicKey, nonce, preparedVote, signature); err != nil {
		t.Fatalf("valid vote signature was rejected: %v", err)
	}

	otherVote := testVote("3d6f5a1b-2c4e-4f8a-9b7c-0e1d2f3a4b5c")
	if err = VerifyVote(publicKey, nonce, []byte(otherVote), signature); err == nil {
		t.Errorf("signature was accepted for a different vote")
	}
	if err = VerifyVote(publicKey, make([]byte, NonceBytes), preparedVote, signature); err == nil {
		t.Errorf("signature was accepted for a different nonce")
	}
}

func TestBlindSignRejectsInvalidBlindedMessages(t *testing.T) {
	privateKey, _ := testElectionKeys(t)

	invalid := map[string][]byte{
		"too short": make([]byte, privateKey.Size()-1),
		"too long":  make([]byte, privateKey.Size()+1),
		"modulus":   privateKey.N.FillBytes(make([]byte, privateKey.Size())),
		// the modulus itself may start with 0xff, so only all 0xff is sure to be above it
		"above the modulus": bytes.Repeat([]byte{0xff}, privateKey.Size()),
	}
	for name, blinded := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := BlindSign(privateKey, blinded); !errors.Is(err, ErrInvalidBlindedMessage) {
				t.Errorf("got error %v, want ErrInvalidBlindedMessage", err)
			}
		})
	}
}
