package localcrypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// RequestSignatureBytes is the length of a request's signature: r and s, each a 48-byte P-384
// integer, concatenated, which is what WebCrypto produces and the only length it checks
const RequestSignatureBytes = 96

// RequestSignedData returns what an authenticated request's signature covers, one field per line in
// this order: the request's action, which names what it does (like "voter.authorize"), the instance
// it was signed for, the role and jurisdiction of the certificate the signer is acting under (empty
// if none), its timestamp, and its body. Only the body can contain a newline, so it goes last and no
// field needs a length prefix. The frontend's signedData builds the same bytes.
func RequestSignedData(action, instance, role, jurisdictionID, timestamp string, body []byte) []byte {
	fields := strings.Join([]string{action, instance, role, jurisdictionID, timestamp}, "\n")
	return append([]byte(fields+"\n"), body...)
}

// ParseRequestTimestamp parses a request's timestamp, in milliseconds since the epoch. It must be in
// decimal form, without a sign or leading zeros, which is how clients write it, so a stored
// request's timestamp reads the same wherever it's checked.
func ParseRequestTimestamp(timestamp string) (parsed int64, err error) {
	parsed, err = strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		err = fmt.Errorf("timestamp is not a number: %w", err)
		return
	}
	// ParseInt also accepts a plus sign and leading zeros
	if strconv.FormatInt(parsed, 10) != timestamp {
		err = errors.New("timestamp is not in canonical form")
		return
	}

	return
}

// DecodeRequestSignature decodes a request's base64 signature, which must be exactly
// RequestSignatureBytes long. ecdsa.Verify would also accept r and s padded with zero bytes, but
// browsers checking the stored request wouldn't, so a client could store a request every audit
// rejects.
func DecodeRequestSignature(encoded string) (signature []byte, err error) {
	signature, err = DecodeBase64(encoded)
	if err != nil {
		return
	}
	if len(signature) != RequestSignatureBytes {
		err = fmt.Errorf("signature is %d bytes instead of %d", len(signature), RequestSignatureBytes)
		return
	}

	return
}

// CanonicalJSON returns the one encoding of a signed request's body that the API accepts: what
// encoding/json produces for it (fields in order and no whitespace), but without escaping <, > and
// &. That's what browsers' JSON.stringify produces, except for U+2028 and U+2029, which encoding/json
// always escapes, so clients escape them too.
func CanonicalJSON(v any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}

	// Encode ends with a newline
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
