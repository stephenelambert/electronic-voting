package vote

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"slices"
	"sort"
	"strconv"
	"testing"

	"electronic-voting/localcrypto"
	"electronic-voting/model"
	"electronic-voting/util/certificate"
	"electronic-voting/util/hashtree"
	"electronic-voting/util/ptr"
	"electronic-voting/util/signedrequest"

	"github.com/google/uuid"
)

// update rewrites the vectors, with new keys and signatures, instead of checking them
var update = flag.Bool("update", false, "rewrite testdata/vectors.json instead of checking it")

const vectorsPath = "testdata/vectors.json"

const vectorElectionID = "a1b2c3d4-e5f6-4789-8abc-def012345678"

// vectorJurisdictionID is the jurisdiction the vectors' election is in
const vectorJurisdictionID = "f1d2c3b4-a5e6-4789-8abc-def012345678"

var vectorCandidateIDs = []string{
	"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
	"6a0c2f7e-3e51-4b7f-8f2c-1d9e8b7a6c5d",
	"3d6f5a1b-2c4e-4f8a-9b7c-0e1d2f3a4b5c",
}

// when the vectors' election opens and closes, and when its jurisdiction was created, as Unix
// timestamps
const (
	vectorTimeOpen  int64 = 1793059200
	vectorTimeClose int64 = vectorTimeOpen + 12*60*60
	vectorCreated   int64 = vectorTimeOpen - 7*24*60*60
)

// vectors are a small election's published votes, with the results that publish them and the proofs
// the API serves once they're published, and the signed requests behind it all, as the API serves
// them, with the certificates they were signed under. The frontend's tests check that the browser
// builds the same tree, accepts these proofs and requests, and rejects altered ones, so if the tree's
// format, the signed data or the certificates change, run this test with -update and make sure both
// pass.
type vectors struct {
	ElectionID string `json:"election_id"`
	// PublicKey is the election key that signed the votes
	PublicKey string `json:"public_key"`
	// Votes are the published votes, in nonce order
	Votes []publishedVoteView `json:"votes"`
	// Results is the body of the admin's request publishing the election's results
	Results string `json:"results"`
	// Proofs are what the API serves for each published vote, and for validly signed votes that
	// aren't in the tree: votes before, between and after them, and one with a published vote's nonce
	Proofs []vectorProof `json:"proofs"`

	// Root issued the certificates the requests below were signed under, and OtherRoot is another
	// instance's root
	Root      vectorRoot `json:"root"`
	OtherRoot vectorRoot `json:"other_root"`
	// Admin is the global admin who created the jurisdiction and the election, authorized every voter
	// but the last and published the results. OtherRootAdminCert is a global admin certificate for
	// the same key, from OtherRoot. SecondAdmin is another global admin, who authorized the last
	// voter, so audits list two admins' keys.
	Admin              vectorSigner `json:"admin"`
	OtherRootAdminCert string       `json:"other_root_admin_cert"`
	SecondAdmin        vectorSigner `json:"second_admin"`
	// Voters are the election's voters, one for each vote, in the order they were authorized
	Voters []vectorSigner `json:"voters"`
	// Jurisdiction, Election, VoterAuthorizations, BlindSignatureRequests and PublishedResults are
	// what the API serves for them
	Jurisdiction           vectorJurisdiction          `json:"jurisdiction"`
	Election               vectorElection              `json:"election"`
	VoterAuthorizations    []vectorAuthorization       `json:"voter_authorizations"`
	BlindSignatureRequests []blindSignatureRequestView `json:"blind_signature_requests"`
	PublishedResults       resultsView                 `json:"published_results"`
}

// vectorRoot is a root certificate and its public key, as GET /api/v1/certificates/root serves them
type vectorRoot struct {
	CertPEM   string `json:"cert_pem"`
	PublicKey string `json:"public_key"`
}

// vectorSigner is a user's public key and the certificate the root issued them, with their private
// key (PKCS #8 PEM). The keys are throwaway ones, and the private key is only there so the frontend's
// tests can sign more requests as the user.
type vectorSigner struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	CertPEM    string `json:"cert_pem"`
}

// vectorJurisdiction is the jurisdiction as GET /api/v1/jurisdictions/{id} serves it
type vectorJurisdiction struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Info             string             `json:"info"`
	CreatedTimestamp int64              `json:"created_timestamp"`
	SignedRequest    signedrequest.View `json:"signed_request"`
}

// vectorCandidate and vectorElection are the election as GET /api/v1/elections/{id} serves it
type vectorCandidate struct {
	ID          string `json:"id"`
	Position    int    `json:"position"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type vectorElection struct {
	ID               string             `json:"id"`
	JurisdictionID   string             `json:"jurisdiction_id"`
	Title            string             `json:"title"`
	Description      string             `json:"description"`
	TimeOpen         int64              `json:"time_open"`
	TimeClose        int64              `json:"time_close"`
	CreatedTimestamp int64              `json:"created_timestamp"`
	PublicKey        string             `json:"public_key"`
	Candidates       []vectorCandidate  `json:"candidates"`
	SignedRequest    signedrequest.View `json:"signed_request"`
}

// vectorAuthorization is a voter authorization as GET /api/v1/jurisdictions/{id}/voter-authorizations
// serves it
type vectorAuthorization struct {
	Certificate   certificate.CertView `json:"certificate"`
	Authorization signedrequest.View   `json:"authorization"`
}

// vectorProof is a vote a client checks, and the proof the API serves for its nonce
type vectorProof struct {
	Vote  publishedVoteView `json:"vote"`
	Proof proofView         `json:"proof"`
}

// signVectorVote returns a vote for the candidate, with a nonce of nonceByte repeated, signed with
// the election key the way RFC 9474 signs it: RSA-PSS with SHA-384 and a 48-byte salt
func signVectorVote(t *testing.T, privateKey *rsa.PrivateKey, nonceByte byte, candidateID string) publishedVoteView {
	t.Helper()

	nonce := bytes.Repeat([]byte{nonceByte}, localcrypto.NonceBytes)
	vote := `{"version":1,"election_id":"` + vectorElectionID + `","candidate_id":"` + candidateID + `"}`

	digest := sha512.Sum384(append(slices.Clone(nonce), vote...))
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA384, digest[:], &rsa.PSSOptions{SaltLength: sha512.Size384})
	if err != nil {
		t.Fatalf("error signing vote: %v", err)
	}
	// checked the way votes are when they're cast
	if err = localcrypto.VerifyVote(&privateKey.PublicKey, nonce, []byte(vote), signature); err != nil {
		t.Fatalf("vote signature doesn't verify: %v", err)
	}

	return publishedVoteView{
		Nonce:     hex.EncodeToString(nonce),
		Vote:      vote,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
}

// vectorTree is the hash tree of the vectors' votes, built the way publishing the results builds it
type vectorTree struct {
	// votes are in nonce order, with their tree positions
	votes []model.Vote
	nodes map[hashtree.NodeID]hashtree.Node
}

// buildVectorTree builds the tree of the published votes, and returns it with the body of the
// request that publishes its results
func buildVectorTree(t *testing.T, published []publishedVoteView) (tree vectorTree, results string) {
	t.Helper()

	leaves := make([]hashtree.Leaf, len(published))
	for i, vote := range published {
		content, err := localcrypto.ParseVote(vote.Vote)
		if err != nil {
			t.Fatalf("invalid vote: %v", err)
		}
		nonce, err := localcrypto.DecodeNonce(vote.Nonce)
		if err != nil {
			t.Fatalf("invalid nonce: %v", err)
		}
		signature, err := localcrypto.DecodeBase64(vote.Signature)
		if err != nil {
			t.Fatalf("invalid signature: %v", err)
		}

		leaves[i] = hashtree.Leaf{Nonce: nonce, Signature: signature, Vote: vote.Vote, CandidateID: content.CandidateID}
		tree.votes = append(tree.votes, model.Vote{
			Nonce:        vote.Nonce,
			Raw:          vote.Vote,
			Signature:    vote.Signature,
			TreePosition: int64(i),
		})
	}

	root, nodes := hashtree.Build(leaves)
	tree.nodes = make(map[hashtree.NodeID]hashtree.Node, len(nodes))
	for _, node := range nodes {
		tree.nodes[node.NodeID] = node
	}

	body, err := localcrypto.CanonicalJSON(resultsRequest{
		ElectionID: vectorElectionID,
		VoteCount:  int64(len(leaves)),
		RootHash:   base64.StdEncoding.EncodeToString(root.Hash[:]),
		Tally:      root.Counts,
	})
	if err != nil {
		t.Fatalf("error encoding results: %v", err)
	}

	return tree, string(body)
}

// proof returns the proof the API serves for the nonce, finding its leaves the way the database
// queries do
func (tree vectorTree) proof(nonce string) proofView {
	i := sort.Search(len(tree.votes), func(i int) bool { return tree.votes[i].Nonce >= nonce })

	leaves := []model.Vote{}
	if i < len(tree.votes) && tree.votes[i].Nonce == nonce {
		leaves = append(leaves, tree.votes[i])
	} else {
		if i > 0 {
			leaves = append(leaves, tree.votes[i-1])
		}
		if i < len(tree.votes) {
			leaves = append(leaves, tree.votes[i])
		}
	}

	return toProofView(voteProof{
		VoteCount: int64(len(tree.votes)),
		Leaves:    leaves,
		Nodes:     tree.nodes,
	})
}

// vectorUser is a user who signs requests in the vectors, under the certificate the root issued them
type vectorUser struct {
	key            *ecdsa.PrivateKey
	role           model.CertificateRole
	jurisdictionID *string
	// publicKey is PEM, in the form the API stores keys in
	publicKey string
	cert      string
}

// encodeVectorPEM encodes DER as PEM, the way the API stores keys and certificates
func encodeVectorPEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// encodeVectorPublicKey encodes a public key as PEM, the way the API stores keys
func encodeVectorPublicKey(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("error encoding public key: %v", err)
	}

	return encodeVectorPEM(localcrypto.PEMStringPublicKey, der)
}

// newVectorRoot makes a root the way localsigner does: a new P-384 key with a self-signed system
// certificate
func newVectorRoot(t *testing.T) (root *x509.Certificate, key *ecdsa.PrivateKey, view vectorRoot) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating root key: %v", err)
	}
	template, err := localcrypto.CreateCertificateTemplate(model.CertificateSystemRole, nil)
	if err != nil {
		t.Fatalf("error creating root certificate template: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("error creating root certificate: %v", err)
	}
	if root, err = x509.ParseCertificate(der); err != nil {
		t.Fatalf("error parsing root certificate: %v", err)
	}

	view = vectorRoot{
		CertPEM:   encodeVectorPEM(localcrypto.PEMStringCertificate, der),
		PublicKey: encodeVectorPublicKey(t, &key.PublicKey),
	}

	return
}

// issueVectorCert issues a certificate for the role in the jurisdiction to the public key, signed by
// the root, the way localsigner does
func issueVectorCert(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, role model.CertificateRole, jurisdictionID *string, publicKey *ecdsa.PublicKey) string {
	t.Helper()

	template, err := localcrypto.CreateCertificateTemplate(role, jurisdictionID)
	if err != nil {
		t.Fatalf("error creating %s certificate template: %v", role, err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, rootKey)
	if err != nil {
		t.Fatalf("error creating %s certificate: %v", role, err)
	}

	return encodeVectorPEM(localcrypto.PEMStringCertificate, der)
}

// newVectorUser makes a user with a new key, which the root issues a certificate for the role in the
// jurisdiction
func newVectorUser(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, role model.CertificateRole, jurisdictionID *string) vectorUser {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating %s key: %v", role, err)
	}

	return vectorUser{
		key:            key,
		role:           role,
		jurisdictionID: jurisdictionID,
		publicKey:      encodeVectorPublicKey(t, &key.PublicKey),
		cert:           issueVectorCert(t, root, rootKey, role, jurisdictionID, &key.PublicKey),
	}
}

// signer returns the user as the vectors list them, with their private key
func (u vectorUser) signer(t *testing.T) vectorSigner {
	t.Helper()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(u.key)
	if err != nil {
		t.Fatalf("error encoding private key: %v", err)
	}

	return vectorSigner{
		PublicKey:  u.publicKey,
		PrivateKey: encodeVectorPEM(localcrypto.PEMStringPrivateKey, privateKeyDER),
		CertPEM:    u.cert,
	}
}

// sign signs a request for the instance at timestamp (a Unix timestamp) as the user, acting under
// their certificate, the way the browser does: ECDSA with SHA-256 over the signed data, as r and s
// concatenated. It returns the request as the API serves it once it's stored.
func (u vectorUser) sign(t *testing.T, instance, action string, timestamp int64, body string) signedrequest.View {
	t.Helper()

	jurisdictionID := ""
	if u.jurisdictionID != nil {
		jurisdictionID = *u.jurisdictionID
	}
	requestTimestamp := strconv.FormatInt(timestamp*1000, 10)

	digest := sha256.Sum256(localcrypto.RequestSignedData(action, instance, string(u.role), jurisdictionID, requestTimestamp, []byte(body)))
	r, s, err := ecdsa.Sign(rand.Reader, u.key, digest[:])
	if err != nil {
		t.Fatalf("error signing %s request: %v", action, err)
	}
	// r and s each take the size of a P-384 integer
	signature := make([]byte, 96)
	r.FillBytes(signature[:48])
	s.FillBytes(signature[48:])

	return signedrequest.View{
		Action:           action,
		Instance:         instance,
		Role:             ptr.Of(u.role),
		JurisdictionID:   u.jurisdictionID,
		RequestTimestamp: requestTimestamp,
		Body:             body,
		PublicKey:        u.publicKey,
		Signature:        base64.StdEncoding.EncodeToString(signature),
		CertPEM:          ptr.Of(u.cert),
	}
}

// encodeVectorBody encodes a request body in the one encoding the API accepts (see
// localcrypto.CanonicalJSON), which the frontend's tests check its canonicalJSON produces too
func encodeVectorBody(t *testing.T, body any) string {
	t.Helper()

	data, err := localcrypto.CanonicalJSON(body)
	if err != nil {
		t.Fatalf("error encoding request body: %v", err)
	}

	return string(data)
}

// generateRecords adds the vectors' election's records to them: the requests that created it and its
// jurisdiction, authorized its voters, asked for blind signatures and published its results, signed
// under certificates from a new root. There's a voter for each vote.
func generateRecords(t *testing.T, v *vectors) {
	t.Helper()

	root, rootKey, rootView := newVectorRoot(t)
	otherRoot, otherRootKey, otherRootView := newVectorRoot(t)
	instance, err := localcrypto.PublicKeyHash(rootView.PublicKey)
	if err != nil {
		t.Fatalf("error hashing root key: %v", err)
	}
	v.Root = rootView
	v.OtherRoot = otherRootView

	admin := newVectorUser(t, root, rootKey, model.CertificateGlobalAdminRole, nil)
	v.Admin = admin.signer(t)
	v.OtherRootAdminCert = issueVectorCert(t, otherRoot, otherRootKey, model.CertificateGlobalAdminRole, nil, &admin.key.PublicKey)
	secondAdmin := newVectorUser(t, root, rootKey, model.CertificateGlobalAdminRole, nil)
	v.SecondAdmin = secondAdmin.signer(t)

	// names and descriptions are free text, so they include characters encoding/json escapes by
	// default but the canonical encoding doesn't (< > &), characters both escape (quotes, backslashes
	// and control characters) and the two only encoding/json escapes (U+2028 and U+2029)
	v.Jurisdiction = vectorJurisdiction{
		ID:               vectorJurisdictionID,
		Name:             "Test County <Board of Elections> & Friends",
		Info:             "Información \"pública\"\nsecond line\twith a \\ backslash, a \b and lines \U00002028 split \U00002029 apart 🗳",
		CreatedTimestamp: vectorCreated,
	}
	// the fields are in the order of the API's request type, as the canonical encoding needs
	v.Jurisdiction.SignedRequest = admin.sign(t, instance, "jurisdiction.create", vectorCreated, encodeVectorBody(t, struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Info string `json:"info"`
	}{
		ID:   v.Jurisdiction.ID,
		Name: v.Jurisdiction.Name,
		Info: v.Jurisdiction.Info,
	}))

	type candidateBody struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	type electionBody struct {
		ID             string          `json:"id"`
		JurisdictionID string          `json:"jurisdiction_id"`
		Title          string          `json:"title"`
		Description    string          `json:"description"`
		TimeOpen       int64           `json:"time_open"`
		TimeClose      int64           `json:"time_close"`
		PublicKey      string          `json:"public_key"`
		Variant        string          `json:"variant"`
		Candidates     []candidateBody `json:"candidates"`
	}
	v.Election = vectorElection{
		ID:               vectorElectionID,
		JurisdictionID:   vectorJurisdictionID,
		Title:            "Mayor & <Council>",
		Description:      "Vote for one. Café ✓",
		TimeOpen:         vectorTimeOpen,
		TimeClose:        vectorTimeClose,
		CreatedTimestamp: vectorCreated + 60*60,
		PublicKey:        v.PublicKey,
	}
	body := electionBody{
		ID:             v.Election.ID,
		JurisdictionID: v.Election.JurisdictionID,
		Title:          v.Election.Title,
		Description:    v.Election.Description,
		TimeOpen:       v.Election.TimeOpen,
		TimeClose:      v.Election.TimeClose,
		PublicKey:      v.Election.PublicKey,
		Variant:        localcrypto.ElectionKeyVariant,
	}
	for i, id := range vectorCandidateIDs {
		candidate := vectorCandidate{
			ID:          id,
			Position:    i,
			Name:        fmt.Sprintf("Candidate <%c>", 'A'+i),
			Description: fmt.Sprintf("\"%c\" & co.", 'A'+i),
		}
		v.Election.Candidates = append(v.Election.Candidates, candidate)
		body.Candidates = append(body.Candidates, candidateBody{ID: candidate.ID, Name: candidate.Name, Description: candidate.Description})
	}
	v.Election.SignedRequest = admin.sign(t, instance, "election.create", v.Election.CreatedTimestamp, encodeVectorBody(t, body))

	keyHash, err := localcrypto.PublicKeyHash(v.PublicKey)
	if err != nil {
		t.Fatalf("error hashing election key: %v", err)
	}
	for i := range v.Votes {
		voter := newVectorUser(t, root, rootKey, model.CertificateVoterRole, ptr.Of(vectorJurisdictionID))
		v.Voters = append(v.Voters, voter.signer(t))

		authorizer := admin
		if i == len(v.Votes)-1 {
			authorizer = secondAdmin
		}
		authorization := authorizer.sign(t, instance, "voter.authorize", v.Election.CreatedTimestamp+int64(i+1)*60, encodeVectorBody(t, struct {
			JurisdictionID string `json:"jurisdiction_id"`
			PublicKey      string `json:"public_key"`
		}{
			JurisdictionID: vectorJurisdictionID,
			PublicKey:      voter.publicKey,
		}))
		v.VoterAuthorizations = append(v.VoterAuthorizations, vectorAuthorization{
			Certificate: certificate.CertView{
				CertPEM:        voter.cert,
				ID:             uuid.NewString(),
				JurisdictionID: voter.jurisdictionID,
				Role:           string(voter.role),
			},
			Authorization: authorization,
		})

		blindedMessage := make([]byte, 256)
		if _, err = rand.Read(blindedMessage); err != nil {
			t.Fatalf("error generating blinded message: %v", err)
		}
		v.BlindSignatureRequests = append(v.BlindSignatureRequests, blindSignatureRequestView{
			SignedRequest: voter.sign(t, instance, "blind_signature.request", vectorTimeOpen+int64(i+1)*60, encodeVectorBody(t, blindSignatureRequest{
				ElectionID:     vectorElectionID,
				BlindedMessage: base64.StdEncoding.EncodeToString(blindedMessage),
				PublicKeyHash:  keyHash,
			})),
			Authorization: authorization,
		})
	}

	v.PublishedResults = resultsView{
		SignedRequest:    admin.sign(t, instance, "results.publish", vectorTimeClose+10*60, v.Results),
		CreatedTimestamp: vectorTimeClose + 10*60,
	}
}

// parseVectorCert parses a PEM certificate
func parseVectorCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("certificate isn't PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("error parsing certificate: %v", err)
	}

	return cert
}

// parseVectorKey parses a PEM ECDSA public key
func parseVectorKey(t *testing.T, publicKeyPEM string) *ecdsa.PublicKey {
	t.Helper()

	_, publicKey, err := localcrypto.NormalizePublicKeyPEM(publicKeyPEM)
	if err != nil {
		t.Fatalf("error parsing public key: %v", err)
	}
	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key isn't ECDSA")
	}

	return ecdsaKey
}

// checkVectorCert checks that the root issued a certificate to the public key, for the role in the
// jurisdiction, with the common name the API gives such certificates
func checkVectorCert(t *testing.T, name, certPEM string, root *x509.Certificate, role model.CertificateRole, jurisdictionID *string, publicKey *ecdsa.PublicKey) {
	t.Helper()

	cert := parseVectorCert(t, certPEM)
	if err := cert.CheckSignatureFrom(root); err != nil {
		t.Errorf("%s wasn't issued by the root: %v", name, err)
	}
	template, err := localcrypto.CreateCertificateTemplate(role, jurisdictionID)
	if err != nil {
		t.Fatalf("error creating %s certificate template: %v", role, err)
	}
	if cert.Subject.CommonName != template.Subject.CommonName {
		t.Errorf("%s's common name is %q, but the API gives %q (run with -update if that changed on purpose)", name, cert.Subject.CommonName, template.Subject.CommonName)
	}
	if !publicKey.Equal(cert.PublicKey) {
		t.Errorf("%s is for another key", name)
	}
}

// checkVectorRequest checks a request's signature the way the API checks one when it's made, and
// that the root issued its certificate to its key, for its role and jurisdiction
func checkVectorRequest(t *testing.T, name string, request signedrequest.View, root *x509.Certificate, instance string) {
	t.Helper()

	if request.Role == nil || request.CertPEM == nil {
		t.Errorf("%s wasn't signed under a certificate", name)
		return
	}
	if request.Instance != instance {
		t.Errorf("%s was signed for another instance", name)
	}

	publicKey := parseVectorKey(t, request.PublicKey)
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil {
		t.Fatalf("%s's signature isn't base64: %v", name, err)
	}
	jurisdictionID := ""
	if request.JurisdictionID != nil {
		jurisdictionID = *request.JurisdictionID
	}
	digest := sha256.Sum256(localcrypto.RequestSignedData(request.Action, request.Instance, string(*request.Role), jurisdictionID, request.RequestTimestamp, []byte(request.Body)))
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		t.Errorf("%s's signature doesn't verify (run with -update if the signed data's format changed on purpose)", name)
	}

	checkVectorCert(t, name+"'s certificate", *request.CertPEM, root, *request.Role, request.JurisdictionID, publicKey)
}

// checkRecords checks the vectors' certificates and signed requests the way the API issues and checks
// them, so they stay in the formats the current code uses
func checkRecords(t *testing.T, v vectors) {
	t.Helper()

	root := parseVectorCert(t, v.Root.CertPEM)
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("root isn't self-signed: %v", err)
	}
	instance, err := localcrypto.PublicKeyHash(v.Root.PublicKey)
	if err != nil {
		t.Fatalf("error hashing root key: %v", err)
	}

	requests := map[string]signedrequest.View{
		"jurisdiction's creation": v.Jurisdiction.SignedRequest,
		"election's creation":     v.Election.SignedRequest,
		"results' publication":    v.PublishedResults.SignedRequest,
	}
	for i, authorization := range v.VoterAuthorizations {
		requests[fmt.Sprintf("voter authorization %d", i+1)] = authorization.Authorization

		// the voter's certificate is for the key the admin authorized
		var body struct {
			PublicKey string `json:"public_key"`
		}
		if err = json.Unmarshal([]byte(authorization.Authorization.Body), &body); err != nil {
			t.Fatalf("error parsing voter authorization %d: %v", i+1, err)
		}
		checkVectorCert(t, fmt.Sprintf("voter certificate %d", i+1), authorization.Certificate.CertPEM, root, model.CertificateVoterRole, authorization.Certificate.JurisdictionID, parseVectorKey(t, body.PublicKey))
	}
	for i, request := range v.BlindSignatureRequests {
		requests[fmt.Sprintf("blind signature request %d", i+1)] = request.SignedRequest
	}
	for name, request := range requests {
		checkVectorRequest(t, name, request, root, instance)
	}

	checkVectorCert(t, "other root's admin certificate", v.OtherRootAdminCert, parseVectorCert(t, v.OtherRoot.CertPEM), model.CertificateGlobalAdminRole, nil, parseVectorKey(t, v.Admin.PublicKey))

	if v.PublishedResults.SignedRequest.Body != v.Results {
		t.Error("published results aren't the vectors' results")
	}
}

// generateVectors makes new vectors, with new keys
func generateVectors(t *testing.T) (v vectors) {
	privateKeyPEM, publicKeyPEM, err := localcrypto.GenerateElectionKey()
	if err != nil {
		t.Fatalf("error generating election key: %v", err)
	}
	privateKey, err := localcrypto.ParseElectionPrivateKey(privateKeyPEM)
	if err != nil {
		t.Fatalf("error parsing election key: %v", err)
	}

	v.ElectionID = vectorElectionID
	v.PublicKey = publicKeyPEM

	// seven votes, so the tree's shape isn't a power of two, with nonces of 0x20 to 0xe0 repeated,
	// which leaves room for nonces between them
	for i := range 7 {
		v.Votes = append(v.Votes, signVectorVote(t, privateKey, byte(0x20*(i+1)), vectorCandidateIDs[i%len(vectorCandidateIDs)]))
	}

	tree, results := buildVectorTree(t, v.Votes)
	v.Results = results

	checked := append(slices.Clone(v.Votes),
		// before the first vote, between the first two, and after the last
		signVectorVote(t, privateKey, 0x10, vectorCandidateIDs[0]),
		signVectorVote(t, privateKey, 0x30, vectorCandidateIDs[1]),
		signVectorVote(t, privateKey, 0xf0, vectorCandidateIDs[2]),
		// the fourth vote's nonce (0x80) with a different candidate
		signVectorVote(t, privateKey, 0x80, vectorCandidateIDs[1]),
	)
	for _, vote := range checked {
		v.Proofs = append(v.Proofs, vectorProof{Vote: vote, Proof: tree.proof(vote.Nonce)})
	}

	generateRecords(t, &v)

	return
}

func TestVectors(t *testing.T) {
	if *update {
		data, err := json.MarshalIndent(generateVectors(t), "", "  ")
		if err != nil {
			t.Fatalf("error encoding vectors: %v", err)
		}
		if err = os.WriteFile(vectorsPath, append(data, '\n'), 0o644); err != nil {
			t.Fatalf("error writing vectors: %v", err)
		}
	}

	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("error reading vectors: %v", err)
	}
	var v vectors
	if err = json.Unmarshal(data, &v); err != nil {
		t.Fatalf("error parsing vectors: %v", err)
	}

	// the stored vectors have to be what the current code builds, since the frontend checks them
	tree, results := buildVectorTree(t, v.Votes)
	if results != v.Results {
		t.Errorf("results are\n%s\nbut the vectors have\n%s\n(run with -update if the tree's format changed on purpose)", results, v.Results)
	}
	for _, p := range v.Proofs {
		got, _ := json.Marshal(tree.proof(p.Vote.Nonce))
		want, _ := json.Marshal(p.Proof)
		if !bytes.Equal(got, want) {
			t.Errorf("proof for nonce %s is\n%s\nbut the vectors have\n%s", p.Vote.Nonce, got, want)
		}
	}

	checkRecords(t, v)
}
