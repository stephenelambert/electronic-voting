package localcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestRequestSignedDataIsExact(t *testing.T) {
	// the same as the signedData tests in the frontend
	cases := map[string]struct {
		action, instance, role, jurisdictionID, timestamp, body string
		want                                                    string
	}{
		"acting under a role": {
			action:    "voter.authorize",
			instance:  "aW5zdGFuY2U=",
			role:      "global_admin",
			timestamp: "1793059200000",
			body:      `{"jurisdiction_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"}`,
			want:      "voter.authorize\naW5zdGFuY2U=\nglobal_admin\n\n1793059200000\n" + `{"jurisdiction_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a"}`,
		},
		"acting under a role in a jurisdiction": {
			action:         "blind_signature.request",
			instance:       "aW5zdGFuY2U=",
			role:           "voter",
			jurisdictionID: "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
			timestamp:      "1793059200000",
			body:           "{\n}",
			want:           "blind_signature.request\naW5zdGFuY2U=\nvoter\n0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a\n1793059200000\n{\n}",
		},
		"only needing the account": {
			action:    "recovery_record.read",
			instance:  "aW5zdGFuY2U=",
			timestamp: "1793059200000",
			want:      "recovery_record.read\naW5zdGFuY2U=\n\n\n1793059200000\n",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := RequestSignedData(c.action, c.instance, c.role, c.jurisdictionID, c.timestamp, []byte(c.body))
			if string(got) != c.want {
				t.Errorf("signed data is %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseRequestTimestamp(t *testing.T) {
	parsed, err := ParseRequestTimestamp("1793059200000")
	if err != nil {
		t.Fatalf("canonical timestamp was rejected: %v", err)
	}
	if parsed != 1793059200000 {
		t.Errorf("timestamp parsed as %d", parsed)
	}

	invalid := map[string]string{
		"empty":         "",
		"plus sign":     "+1793059200000",
		"leading zero":  "01793059200000",
		"fraction":      "1793059200000.0",
		"exponent":      "1.7930592e12",
		"space":         " 1793059200000",
		"not a number":  "now",
		"out of range":  "99999999999999999999",
		"negative zero": "-0",
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequestTimestamp(value); err == nil {
				t.Errorf("timestamp %q was accepted", value)
			}
		})
	}
}

func TestDecodeRequestSignature(t *testing.T) {
	signature := make([]byte, RequestSignatureBytes)
	if _, err := rand.Read(signature); err != nil {
		t.Fatalf("error generating signature: %v", err)
	}

	decoded, err := DecodeRequestSignature(base64.StdEncoding.EncodeToString(signature))
	if err != nil {
		t.Fatalf("%d-byte signature was rejected: %v", RequestSignatureBytes, err)
	}
	if !bytes.Equal(decoded, signature) {
		t.Errorf("decoded signature doesn't match")
	}

	encoded := base64.StdEncoding.EncodeToString(signature)
	// padding r and s with zero bytes gives a signature ecdsa.Verify still accepts
	padded := append(append([]byte{0}, signature[:48]...), append([]byte{0}, signature[48:]...)...)
	invalid := map[string]string{
		"short":               base64.StdEncoding.EncodeToString(signature[1:]),
		"long":                base64.StdEncoding.EncodeToString(append(signature, 0)),
		"r and s padded":      base64.StdEncoding.EncodeToString(padded),
		"half of a signature": base64.StdEncoding.EncodeToString(signature[:48]),
		"newline":             encoded[:64] + "\n" + encoded[64:],
		"not base64":          strings.Repeat("!", len(encoded)),
		"empty":               "",
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequestSignature(value); err == nil {
				t.Errorf("signature %q was accepted", value)
			}
		})
	}
}

func TestCanonicalJSONIsExact(t *testing.T) {
	// the same as the canonicalJSON test in the frontend: < > & aren't escaped, quotes, backslashes and
	// control characters are, and U+2028 and U+2029 are, as encoding/json always escapes them
	body := struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Count int64  `json:"count"`
	}{
		ID:    "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
		Name:  "<b>Tom & \"Jerry\"</b> \\ \n\t\b\f\u0001\u007f \U00002028\U00002029 é🗳",
		Count: 3,
	}

	got, err := CanonicalJSON(body)
	if err != nil {
		t.Fatalf("error encoding body: %v", err)
	}
	want := `{"id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a","name":"<b>Tom & \"Jerry\"</b> \\ \n\t\b\f\u0001` + "\u007f \\u2028\\u2029 " + `é🗳","count":3}`
	if string(got) != want {
		t.Errorf("body is\n%s\nwant\n%s", got, want)
	}
}
