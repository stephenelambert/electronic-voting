package localcrypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// NonceBytes is the length of a vote's nonce: the random prefix that RFC 9474's randomized variants
// add to a message before it is blinded
const NonceBytes = 32

// VoteVersion is the version of the vote format that votes are cast in
const VoteVersion = 1

// ErrInvalidBlindedMessage is returned by BlindSign when the blinded message can't have come from
// blinding a message under the key
var ErrInvalidBlindedMessage = errors.New("blinded message is not a valid size for the election key")

// VoteContent is the vote JSON that the election key signs, after the nonce. Its fields are in the
// order of the one encoding votes are accepted in.
type VoteContent struct {
	Version     int    `json:"version"`
	ElectionID  string `json:"election_id"`
	CandidateID string `json:"candidate_id"`
}

// ParseVote parses vote JSON, which must be exactly what json.Marshal produces for a VoteContent:
// fields in order, no whitespace or other fields, and canonical UUIDs. Votes are signed blind, so
// casting is the first time their content is checked, and everyone who counts them needs to accept
// exactly the same votes.
func ParseVote(raw string) (vote VoteContent, err error) {
	if err = json.Unmarshal([]byte(raw), &vote); err != nil {
		err = fmt.Errorf("vote is not valid JSON: %w", err)
		return
	}

	// whitespace, other fields, other field orders, repeated fields and escapes don't survive the
	// round trip, so they are all rejected here
	canonical, err := json.Marshal(vote)
	if err != nil {
		err = fmt.Errorf("error re-encoding vote: %w", err)
		return
	}
	if !bytes.Equal(canonical, []byte(raw)) {
		err = errors.New("vote is not in canonical form")
		return
	}

	if vote.Version != VoteVersion {
		err = fmt.Errorf("vote version %d is not supported", vote.Version)
		return
	}
	// the round trip keeps the case of the ids, so they need their own check
	if !UUIDIsCanonical(vote.ElectionID) || !UUIDIsCanonical(vote.CandidateID) {
		err = errors.New("vote ids are not canonical uuids")
		return
	}

	return
}

// DecodeNonce decodes a vote's nonce from lowercase hex, the only form it is accepted and stored in,
// so nonces sort and compare the same everywhere
func DecodeNonce(nonceHex string) (nonce []byte, err error) {
	nonce, err = hex.DecodeString(nonceHex)
	if err != nil {
		err = fmt.Errorf("nonce is not hex: %w", err)
		return
	}
	if len(nonce) != NonceBytes {
		err = fmt.Errorf("nonce is %d bytes instead of %d", len(nonce), NonceBytes)
		return
	}
	// hex.DecodeString also accepts uppercase
	if hex.EncodeToString(nonce) != nonceHex {
		err = errors.New("nonce is not lowercase hex")
		return
	}

	return
}

// DecodeBase64 decodes standard base64, accepting only the encoding EncodeToString produces, so a
// value compares equal to every other encoding of the same bytes
func DecodeBase64(encoded string) (decoded []byte, err error) {
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		err = fmt.Errorf("value is not base64: %w", err)
		return
	}
	// DecodeString ignores newlines and nonzero padding bits
	if base64.StdEncoding.EncodeToString(decoded) != encoded {
		err = errors.New("value is not in canonical base64")
		return
	}

	return
}

// PublicKeyHash returns the base64 SHA-256 hash of a PEM public key's DER encoding. Requests for
// blind signatures include it to name the election key the voter blinded their vote under.
func PublicKeyHash(publicKeyPEM string) (hash string, err error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		err = errors.New("public key is not valid PEM")
		return
	}

	digest := sha256.Sum256(block.Bytes)
	hash = base64.StdEncoding.EncodeToString(digest[:])

	return
}

// ParseElectionPrivateKey parses an election's private key from PKCS #8 PEM, the form
// GenerateElectionKey produces
func ParseElectionPrivateKey(privateKeyPEM string) (privateKey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		err = errors.New("election private key is not valid PEM")
		return
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		err = fmt.Errorf("error parsing election private key: %w", err)
		return
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		err = errors.New("election private key is not an rsa key")
		return
	}

	return
}

// ParseElectionPublicKey parses an election's public key from PKIX PEM
func ParseElectionPublicKey(publicKeyPEM string) (publicKey *rsa.PublicKey, err error) {
	_, key, err := NormalizePublicKeyPEM(publicKeyPEM)
	if err != nil {
		err = fmt.Errorf("error parsing election public key: %w", err)
		return
	}

	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		err = errors.New("election public key is not an rsa key")
		return
	}

	return
}

// BlindSign signs a blinded vote with an election's private key, as RFC 9474's BlindSign does. The
// signature is still blinded, so only the voter's client can unblind it. ErrInvalidBlindedMessage
// is returned if the blinded message isn't the size of the key's modulus or isn't less than it.
func BlindSign(privateKey *rsa.PrivateKey, blindedMessage []byte) (blindSignature []byte, err error) {
	// checked here rather than left to the signer, so its errors only mean something went wrong on
	// the server
	if len(blindedMessage) != privateKey.Size() || new(big.Int).SetBytes(blindedMessage).Cmp(privateKey.N) >= 0 {
		err = ErrInvalidBlindedMessage
		return
	}

	blindSignature, err = blindrsa.NewSigner(privateKey).BlindSign(blindedMessage)
	if err != nil {
		err = fmt.Errorf("error signing blinded message: %w", err)
		return
	}

	return
}

// VerifyVote checks that signature is the election key's signature over the vote's nonce followed by
// the vote, with the variant election keys are used with (ElectionKeyVariant)
func VerifyVote(publicKey *rsa.PublicKey, nonce, vote, signature []byte) (err error) {
	verifier, err := blindrsa.NewVerifier(blindrsa.SHA384PSSRandomized, publicKey)
	if err != nil {
		err = fmt.Errorf("error creating vote verifier: %w", err)
		return
	}

	message := make([]byte, 0, len(nonce)+len(vote))
	message = append(message, nonce...)
	message = append(message, vote...)

	if err = verifier.Verify(message, signature); err != nil {
		err = fmt.Errorf("vote signature is invalid: %w", err)
		return
	}

	return
}
