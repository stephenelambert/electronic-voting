package dbcrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

// formats are the formats pgx sends and receives bytea in: binary for the extended protocol, which
// the API uses, and text for the simple protocol
var formats = map[string]int16{
	"binary": pgtype.BinaryFormatCode,
	"text":   pgtype.TextFormatCode,
}

// setUpKey sets the package up with a new random key
func setUpKey(t *testing.T) {
	t.Helper()

	key := make([]byte, keyLength)
	_, _ = rand.Read(key)
	t.Setenv(KeyEnvVar, base64.StdEncoding.EncodeToString(key))

	if err := Init(); err != nil {
		t.Fatalf("error setting up key: %v", err)
	}
}

// roundTrip encodes value as a query argument and scans it back the way pgx does, checking that
// what the database would store is encrypted and that the scanned value is the original. It goes
// through pgx rather than calling Value and Scan directly, since some pgx versions skip them for
// types with an underlying string or []byte.
func roundTrip[T EncryptedString | EncryptedBytes](t *testing.T, m *pgtype.Map, format int16, value T) {
	t.Helper()

	var stored [2][]byte
	var encoded []byte
	for i := range stored {
		var err error
		encoded, err = m.Encode(pgtype.ByteaOID, format, value, nil)
		if err != nil {
			t.Fatalf("error encoding %T: %v", value, err)
		}
		if err = m.Scan(pgtype.ByteaOID, format, encoded, &stored[i]); err != nil {
			t.Fatalf("error decoding stored %T: %v", value, err)
		}
	}

	if len(stored[0]) != 1+aesKey.Overhead()+len(value) || stored[0][0] != version {
		t.Fatalf("stored %T isn't version, nonce, ciphertext and tag: %x", value, stored[0])
	}
	if bytes.Contains(stored[0], []byte(value)) {
		t.Errorf("stored %T contains the plaintext", value)
	}
	if bytes.Equal(stored[0], stored[1]) {
		t.Errorf("%T was encrypted the same way twice", value)
	}

	var scanned T
	if err := m.Scan(pgtype.ByteaOID, format, encoded, &scanned); err != nil {
		t.Fatalf("error scanning %T: %v", value, err)
	}
	if !bytes.Equal([]byte(scanned), []byte(value)) {
		t.Errorf("%T scanned as %q, not %q", value, scanned, value)
	}
}

func TestRoundTrip(t *testing.T) {
	setUpKey(t)
	m := pgtype.NewMap()

	for name, format := range formats {
		t.Run(name, func(t *testing.T) {
			roundTrip(t, m, format, EncryptedString("correct horse battery staple"))
			roundTrip(t, m, format, EncryptedBytes{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff})
		})
	}
}

// TestNullableString checks *EncryptedString fields, which is how nullable string columns are scanned
// and inserted
func TestNullableString(t *testing.T) {
	setUpKey(t)
	m := pgtype.NewMap()

	value := EncryptedString("correct horse battery staple")
	encoded, err := m.Encode(pgtype.ByteaOID, pgtype.BinaryFormatCode, value, nil)
	if err != nil {
		t.Fatalf("error encoding value: %v", err)
	}

	var scanned *EncryptedString
	if err = m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, encoded, &scanned); err != nil {
		t.Fatalf("error scanning value into a pointer: %v", err)
	}
	if scanned == nil || *scanned != value {
		t.Errorf("value scanned into a pointer as %v", scanned)
	}

	if err = m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, nil, &scanned); err != nil {
		t.Fatalf("error scanning NULL into a pointer: %v", err)
	}
	if scanned != nil {
		t.Errorf("NULL scanned into a pointer as %q", *scanned)
	}

	var notNullable EncryptedString
	if err = m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, nil, &notNullable); err == nil {
		t.Error("NULL was scanned into a non-pointer field")
	}

	var missing *EncryptedString
	encoded, err = m.Encode(pgtype.ByteaOID, pgtype.BinaryFormatCode, missing, nil)
	if err != nil {
		t.Fatalf("error encoding nil pointer: %v", err)
	}
	if encoded != nil {
		t.Errorf("nil pointer was encoded as %x, not NULL", encoded)
	}
}

// TestNilBytes checks that a nil EncryptedBytes is stored as NULL and NULL is scanned as nil, while
// an empty one stays empty rather than becoming NULL
func TestNilBytes(t *testing.T) {
	setUpKey(t)
	m := pgtype.NewMap()

	encoded, err := m.Encode(pgtype.ByteaOID, pgtype.BinaryFormatCode, EncryptedBytes(nil), nil)
	if err != nil {
		t.Fatalf("error encoding nil: %v", err)
	}
	if encoded != nil {
		t.Errorf("nil was encoded as %x, not NULL", encoded)
	}

	scanned := EncryptedBytes{0x01}
	if err = m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, nil, &scanned); err != nil {
		t.Fatalf("error scanning NULL: %v", err)
	}
	if scanned != nil {
		t.Errorf("NULL scanned as %x, not nil", scanned)
	}

	encoded, err = m.Encode(pgtype.ByteaOID, pgtype.BinaryFormatCode, EncryptedBytes{}, nil)
	if err != nil {
		t.Fatalf("error encoding empty value: %v", err)
	}
	if encoded == nil {
		t.Fatal("empty value was encoded as NULL")
	}
	if err = m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, encoded, &scanned); err != nil {
		t.Fatalf("error scanning empty value: %v", err)
	}
	if scanned == nil || len(scanned) != 0 {
		t.Errorf("empty value scanned as %#v", scanned)
	}
}

// TestMalformed checks that stored values that weren't encrypted with the key are rejected, rather
// than causing a panic or being scanned as they are
func TestMalformed(t *testing.T) {
	setUpKey(t)
	otherKey, err := seal([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("error encrypting with other key: %v", err)
	}

	setUpKey(t)
	valid, err := seal([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("error encrypting: %v", err)
	}

	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1] ^= 0x01
	otherVersion := bytes.Clone(valid)
	otherVersion[0] = version + 1

	cases := map[string][]byte{
		"empty":         {},
		"version only":  {version},
		"other version": otherVersion,
		"truncated":     valid[:len(valid)-1],
		"tampered":      tampered,
		"other key":     otherKey,
		"plaintext":     []byte("correct horse battery staple"),
	}

	m := pgtype.NewMap()
	for name, stored := range cases {
		t.Run(name, func(t *testing.T) {
			// in the binary format, a bytea is sent as its bytes
			var str EncryptedString
			if err := m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, stored, &str); err == nil {
				t.Errorf("string was scanned as %q", str)
			}

			var b EncryptedBytes
			if err := m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, stored, &b); err == nil {
				t.Errorf("bytes were scanned as %x", b)
			}
		})
	}

	// the likeliest cause in practice is the wrong key, so the error points to it
	var str EncryptedString
	err = m.Scan(pgtype.ByteaOID, pgtype.BinaryFormatCode, otherKey, &str)
	if err == nil || !strings.Contains(err.Error(), KeyEnvVar) {
		t.Errorf("error for another key's value doesn't name the environment variable: %v", err)
	}
}

func TestInit(t *testing.T) {
	key := make([]byte, keyLength)
	_, _ = rand.Read(key)

	t.Setenv(KeyEnvVar, base64.StdEncoding.EncodeToString(key))
	if err := Init(); err != nil {
		t.Fatalf("valid key was rejected: %v", err)
	}

	cases := map[string]string{
		"missing":    "",
		"not base64": strings.Repeat("!", 44),
		// a valid AES-128 key
		"too short": base64.StdEncoding.EncodeToString(key[:16]),
		"too long":  base64.StdEncoding.EncodeToString(append(key, 0)),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(KeyEnvVar, value)

			err := Init()
			if err == nil {
				t.Fatal("invalid key was accepted")
			}
			if !strings.Contains(err.Error(), KeyEnvVar) {
				t.Errorf("error doesn't name the environment variable: %v", err)
			}
			if value != "" && strings.Contains(err.Error(), value) {
				t.Errorf("error includes the key: %v", err)
			}
		})
	}
}
