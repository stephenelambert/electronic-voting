package localopaque

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/bytemare/opaque"
)

// clientOptions makes the test clients' key stretching cheap (Argon2id with 1 pass over 64 KiB). Key
// stretching only happens in the client, so the server works the same with any settings.
func clientOptions() *opaque.ClientOptions {
	return &opaque.ClientOptions{KSFParameters: []uint64{1, 64, 1}}
}

// setUpServer sets up the package's server with a new seed and key pair
func setUpServer(t *testing.T) {
	t.Helper()

	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	privateKey, publicKey := generateKey()

	s, err := newServer(seed, privateKey, publicKey)
	if err != nil {
		t.Fatalf("error setting up server: %v", err)
	}
	server = s
}

func newClient(t *testing.T) *opaque.Client {
	t.Helper()

	client, err := opaque.DefaultConfiguration().Client()
	if err != nil {
		t.Fatalf("error creating client: %v", err)
	}

	return client
}

// register registers username with password, like the frontend does, returning the record as it's
// stored and the client's export key
func register(t *testing.T, username, password string) (record, exportKey []byte) {
	t.Helper()

	client := newClient(t)
	request, err := client.RegistrationInit([]byte(password))
	if err != nil {
		t.Fatalf("error starting registration: %v", err)
	}

	response, err := RegistrationResponse(username, encoding.EncodeToString(request.Serialize()))
	if err != nil {
		t.Fatalf("error answering registration request: %v", err)
	}
	rawResponse, err := encoding.DecodeString(response)
	if err != nil {
		t.Fatalf("registration response isn't unpadded base64url: %v", err)
	}
	parsedResponse, err := client.Deserialize.RegistrationResponse(rawResponse)
	if err != nil {
		t.Fatalf("error decoding registration response: %v", err)
	}

	// no server identity, like the frontend, so the client uses the server's public key
	clientRecord, exportKey, err := client.RegistrationFinalize(parsedResponse, []byte(username), nil, clientOptions())
	if err != nil {
		t.Fatalf("error finishing registration: %v", err)
	}

	record, err = ParseRecord(encoding.EncodeToString(clientRecord.Serialize()))
	if err != nil {
		t.Fatalf("error parsing registration record: %v", err)
	}

	return record, exportKey
}

// login runs a login for username with password against record, returning the client's KE3 and
// export key (or the client's error) and the MAC the server expects
func login(t *testing.T, username, password string, record []byte) (ke3 string, exportKey, expectedMAC []byte, clientErr error) {
	t.Helper()

	client := newClient(t)
	ke1, err := client.GenerateKE1([]byte(password))
	if err != nil {
		t.Fatalf("error generating KE1: %v", err)
	}

	ke2, expectedMAC, err := StartLogin(username, record, encoding.EncodeToString(ke1.Serialize()))
	if err != nil {
		t.Fatalf("error starting login: %v", err)
	}

	rawKE2, err := encoding.DecodeString(ke2)
	if err != nil {
		t.Fatalf("KE2 isn't unpadded base64url: %v", err)
	}
	parsedKE2, err := client.Deserialize.KE2(rawKE2)
	if err != nil {
		t.Fatalf("error decoding KE2: %v", err)
	}

	parsedKE3, _, exportKey, clientErr := client.GenerateKE3(parsedKE2, []byte(username), nil, clientOptions())
	if clientErr != nil {
		return "", nil, expectedMAC, clientErr
	}

	return encoding.EncodeToString(parsedKE3.Serialize()), exportKey, expectedMAC, nil
}

func TestParseOPRFSeed(t *testing.T) {
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	encoded := base64.StdEncoding.EncodeToString(seed)

	parsed, err := ParseOPRFSeed(encoded)
	if err != nil {
		t.Fatalf("valid seed was rejected: %v", err)
	}
	if !bytes.Equal(parsed, seed) {
		t.Error("seed decoded differently")
	}

	// openssl wraps base64 at 64 characters, and line breaks are skipped
	if _, err = ParseOPRFSeed(encoded[:64] + "\n" + encoded[64:] + "\n"); err != nil {
		t.Errorf("seed with openssl's line break was rejected: %v", err)
	}

	short := base64.StdEncoding.EncodeToString(seed[:32])
	cases := map[string]string{
		"missing":            "",
		"not base64":         strings.Repeat("!", 88),
		"too short":          short,
		"too long":           base64.StdEncoding.EncodeToString(append(seed, 0)),
		"without padding":    base64.RawStdEncoding.EncodeToString(seed),
		"base64url alphabet": base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 64)),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOPRFSeed(value); err == nil {
				t.Error("invalid seed was accepted")
			} else if !strings.Contains(err.Error(), OPRFSeedEnvVar) {
				t.Errorf("error doesn't name the environment variable: %v", err)
			}
		})
	}
}

func TestRegisterAndLogin(t *testing.T) {
	setUpServer(t)

	record, registrationExportKey := register(t, "alice", "correct horse battery staple")

	for range 2 {
		ke3, exportKey, expectedMAC, err := login(t, "alice", "correct horse battery staple", record)
		if err != nil {
			t.Fatalf("client rejected the server's KE2: %v", err)
		}
		if err = FinishLogin(ke3, expectedMAC); err != nil {
			t.Fatalf("server rejected the client's KE3: %v", err)
		}
		// the frontend wraps the account's AES key with a key from the export key, so it can't change
		if !bytes.Equal(exportKey, registrationExportKey) {
			t.Error("export key differs from registration's")
		}
	}
}

func TestWrongPasswordFailsInTheClient(t *testing.T) {
	setUpServer(t)

	record, _ := register(t, "alice", "correct horse battery staple")

	if _, _, _, err := login(t, "alice", "correct horse battery stapler", record); err == nil {
		t.Error("client finished a login with the wrong password")
	}
}

func TestRecordOnlyWorksForItsUsername(t *testing.T) {
	setUpServer(t)

	// each username has its own OPRF key, so alice's record answered under bob's name doesn't open
	record, _ := register(t, "alice", "correct horse battery staple")

	if _, _, _, err := login(t, "bob", "correct horse battery staple", record); err == nil {
		t.Error("client finished a login with another username's record")
	}
}

func TestSamePasswordGivesDifferentExportKeys(t *testing.T) {
	setUpServer(t)

	_, alice := register(t, "alice", "pa55word")
	_, bob := register(t, "bob", "pa55word")
	if bytes.Equal(alice, bob) {
		t.Error("two accounts with the same password have the same export key")
	}
}

func TestFinishLoginRejectsOtherKE3s(t *testing.T) {
	setUpServer(t)

	record, _ := register(t, "alice", "correct horse battery staple")
	ke3, _, _, err := login(t, "alice", "correct horse battery staple", record)
	if err != nil {
		t.Fatalf("client rejected the server's KE2: %v", err)
	}
	_, _, otherMAC, err := login(t, "alice", "correct horse battery staple", record)
	if err != nil {
		t.Fatalf("client rejected the server's KE2: %v", err)
	}

	if err = FinishLogin(ke3, otherMAC); err == nil {
		t.Error("KE3 from one login finished another")
	}

	raw, _ := encoding.DecodeString(ke3)
	raw[0] ^= 1
	_, _, mac, err := login(t, "alice", "correct horse battery staple", record)
	if err != nil {
		t.Fatalf("client rejected the server's KE2: %v", err)
	}
	if err = FinishLogin(encoding.EncodeToString(raw), mac); err == nil {
		t.Error("tampered KE3 was accepted")
	}
}

func TestInvalidMessages(t *testing.T) {
	setUpServer(t)

	record, _ := register(t, "alice", "correct horse battery staple")
	garbage := encoding.EncodeToString(bytes.Repeat([]byte{0xff}, 96))

	for name, value := range map[string]string{"not base64url": "***", "not a message": garbage, "padded": "AAAA=="} {
		t.Run(name, func(t *testing.T) {
			if _, err := RegistrationResponse("alice", value); !errors.Is(err, ErrInvalidMessage) {
				t.Errorf("registration request: got %v, want ErrInvalidMessage", err)
			}
			if _, err := ParseRecord(value); !errors.Is(err, ErrInvalidMessage) {
				t.Errorf("registration record: got %v, want ErrInvalidMessage", err)
			}
			if _, _, err := StartLogin("alice", record, value); !errors.Is(err, ErrInvalidMessage) {
				t.Errorf("KE1: got %v, want ErrInvalidMessage", err)
			}
			if err := FinishLogin(value, make([]byte, 64)); err == nil {
				t.Error("KE3 was accepted")
			}
		})
	}
}

func TestNewServerChecksTheKeyPair(t *testing.T) {
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	privateKey, _ := generateKey()
	_, otherPublicKey := generateKey()

	if _, err := newServer(seed, privateKey, otherPublicKey); err == nil {
		t.Error("server was set up with another key pair's public key")
	}
}
