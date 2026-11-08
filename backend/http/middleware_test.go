package http

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"electronic-voting/util/ctxkey"

	"github.com/jackc/pgx/v5"
)

// signatureBody stands in for a response that can't be taken back once it's sent, like a blind
// signature
const signatureBody = `{"blind_signature":"c2lnbmF0dXJl"}`

// fakeTx is a transaction whose Commit and Rollback act like pgx's: neither reaches the database if
// its context is done, and neither works once the transaction is closed. Its other methods panic.
type fakeTx struct {
	pgx.Tx

	// commitErr, if set, is returned by Commit instead of committing, like a lost connection
	commitErr error

	closed     atomic.Bool
	committed  atomic.Bool
	rolledBack atomic.Bool
}

func (tx *fakeTx) Commit(ctx context.Context) error {
	if tx.closed.Swap(true) {
		return pgx.ErrTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx.commitErr != nil {
		return tx.commitErr
	}

	tx.committed.Store(true)
	return nil
}

func (tx *fakeTx) Rollback(ctx context.Context) error {
	if tx.closed.Swap(true) {
		return pgx.ErrTxClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	tx.rolledBack.Store(true)
	return nil
}

// withTx wraps handler the way the API router does, but with tx as every request's transaction
func withTx(tx *fakeTx, handler http.HandlerFunc) http.Handler {
	beginTx := func(context.Context) (pgx.Tx, error) {
		return tx, nil
	}
	return txToCtx(beginTx, handler)
}

// writeSignature responds like a handler that has done its work and is returning a blind signature
func writeSignature(w http.ResponseWriter) {
	w.Header().Set("X-Handler", "signed")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(signatureBody))
}

func TestTxToCtxSendsResponseAfterCommit(t *testing.T) {
	tx := &fakeTx{}
	handler := withTx(tx, func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(ctxkey.Key("transaction")) != any(tx) {
			t.Error("handler didn't get the transaction")
		}
		writeSignature(w)
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if !tx.committed.Load() {
		t.Error("transaction wasn't committed")
	}
	if rec.Code != http.StatusCreated || rec.Body.String() != signatureBody || rec.Header().Get("X-Handler") != "signed" {
		t.Errorf("got %d %q with headers %v, want the handler's response", rec.Code, rec.Body.String(), rec.Header())
	}
}

func TestTxToCtxDropsResponseWhenCommitFails(t *testing.T) {
	tx := &fakeTx{commitErr: errors.New("connection lost")}
	handler := withTx(tx, func(w http.ResponseWriter, r *http.Request) {
		writeSignature(w)
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if tx.committed.Load() {
		t.Error("transaction was committed")
	}
	// the response may hold something that can't be taken back, so none of it is sent
	if rec.Code != http.StatusInternalServerError || rec.Body.Len() != 0 || rec.Header().Get("X-Handler") != "" {
		t.Errorf("got %d %q with headers %v, want a bare 500", rec.Code, rec.Body.String(), rec.Header())
	}
}

func TestTxToCtxRollsBackErrorResponses(t *testing.T) {
	tx := &fakeTx{}
	handler := withTx(tx, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("conflict"))
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if tx.committed.Load() || !tx.rolledBack.Load() {
		t.Errorf("committed %v and rolled back %v, want only rolled back", tx.committed.Load(), tx.rolledBack.Load())
	}
	if rec.Code != http.StatusConflict || rec.Body.String() != "conflict" {
		t.Errorf("got %d %q, want the handler's 409", rec.Code, rec.Body.String())
	}
}

func TestTxToCtxDropsResponseOnPanic(t *testing.T) {
	tx := &fakeTx{}
	handler := withTx(tx, func(w http.ResponseWriter, r *http.Request) {
		writeSignature(w)
		panic("handler failed after writing its response")
	})

	rec := httptest.NewRecorder()
	func() {
		// the panic goes on to Go's HTTP server, which logs it and closes the connection
		defer func() {
			if recover() == nil {
				t.Error("the handler's panic didn't reach the server")
			}
		}()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	}()

	if tx.committed.Load() || !tx.rolledBack.Load() {
		t.Errorf("committed %v and rolled back %v, want only rolled back", tx.committed.Load(), tx.rolledBack.Load())
	}
	// the response TxToCtx was holding is never sent
	if rec.Body.Len() != 0 || rec.Header().Get("X-Handler") != "" {
		t.Errorf("client got %q with headers %v, want nothing", rec.Body.String(), rec.Header())
	}
}

func TestTxToCtxCommitsAfterClientDisconnects(t *testing.T) {
	ctx, disconnect := context.WithCancel(context.Background())
	defer disconnect()

	tx := &fakeTx{}
	handler := withTx(tx, func(w http.ResponseWriter, r *http.Request) {
		writeSignature(w)
		// the client goes away once the handler's work is done, which shouldn't undo the work
		disconnect()
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodPost, "/", nil))

	if !tx.committed.Load() {
		t.Error("transaction wasn't committed")
	}
	if rec.Code != http.StatusCreated || rec.Body.String() != signatureBody {
		t.Errorf("got %d %q, want the handler's response", rec.Code, rec.Body.String())
	}
}

// TestTxToCtxHalfClosedClient covers a client that closes its side of the connection right after
// sending its request, which still lets it read the response. Go's HTTP server cancels the
// request's context when it sees that, and TxToCtx used to send the handler's response (a blind
// signature, say) even though the cancelled context had stopped the commit.
func TestTxToCtxHalfClosedClient(t *testing.T) {
	tx := &fakeTx{}
	cancelled := make(chan bool, 1)
	server := httptest.NewServer(withTx(tx, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		writeSignature(w)

		// wait for the server to see the half close, so it lands after the handler's work and
		// before the commit
		select {
		case <-r.Context().Done():
			cancelled <- true
		case <-time.After(5 * time.Second):
			cancelled <- false
		}
	}))
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("error connecting to test server: %v", err)
	}
	defer conn.Close() //nolint:all

	if _, err = io.WriteString(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 2\r\n\r\n{}"); err != nil {
		t.Fatalf("error sending request: %v", err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("error half closing connection: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("error reading response: %v", err)
	}
	defer resp.Body.Close() //nolint:all
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body: %v", err)
	}

	if !<-cancelled {
		t.Fatal("server didn't cancel the request's context when the client half closed")
	}
	// the signature may only reach the client if the transaction that records it committed
	if strings.Contains(string(body), signatureBody) && !tx.committed.Load() {
		t.Errorf("client got %d %q, but the transaction wasn't committed", resp.StatusCode, body)
	}
}

// testSignedBody is a signed request body with an ID, a hash and free text, like the API's
type testSignedBody struct {
	ElectionID    string `json:"election_id"`
	PublicKeyHash string `json:"public_key_hash"`
	Name          string `json:"name"`
}

func TestCanonicalDtoToCtx(t *testing.T) {
	// the name ends with U+2028, which the canonical encoding escapes
	escapedSeparator := "\\u2028"
	canonical := `{"election_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a","public_key_hash":"aGFzaA==","name":"<Tom> & \"Jerry\" ` + escapedSeparator + `"}`
	want := testSignedBody{
		ElectionID:    "0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a",
		PublicKeyHash: "aGFzaA==",
		Name:          "<Tom> & \"Jerry\" \U00002028",
	}

	// send returns the status for a request with the body, and what the handler got from it
	send := func(body string) (int, *testSignedBody) {
		var got *testSignedBody
		handler := CanonicalDtoToCtx[testSignedBody]("dto", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Context().Value(ctxkey.Key("dto")).(*testSignedBody)
			w.WriteHeader(http.StatusOK)
		}))

		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxkey.Key("request_body"), []byte(body)))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code, got
	}

	status, got := send(canonical)
	if status != http.StatusOK {
		t.Fatalf("canonical body got status %d", status)
	}
	if *got != want {
		t.Errorf("handler got %+v, want %+v", *got, want)
	}

	// encoding/json reads each of these the same as the canonical body, though browsers don't all,
	// or they're another encoding of it
	invalid := map[string]string{
		"unknown field":              strings.TrimSuffix(canonical, "}") + `,"extra":1}`,
		"field name in another case": strings.Replace(canonical, `"election_id"`, `"Election_ID"`, 1),
		// ſ (long s) folds to s
		"field name that folds to the field's": strings.Replace(canonical, `"public_key_hash"`, `"public_key_haſh"`, 1),
		"repeated field":                       strings.Replace(canonical, `"public_key_hash":"aGFzaA=="`, `"public_key_hash":"b3RoZXI=","public_key_hash":"aGFzaA=="`, 1),
		"fields in another order":              `{"public_key_hash":"aGFzaA==","election_id":"0b8f4f9e-9a52-4f3e-9d43-3c3b2b3f6b1a","name":"<Tom> & \"Jerry\" ` + escapedSeparator + `"}`,
		"whitespace":                           strings.Replace(canonical, `,"name"`, `, "name"`, 1),
		"escaped letter":                       strings.Replace(canonical, "Tom", `\u0054om`, 1),
		"encoding/json's default escapes":      strings.Replace(strings.Replace(strings.Replace(canonical, "<", `\u003c`, 1), ">", `\u003e`, 1), "&", `\u0026`, 1),
		"unescaped line separator":             strings.Replace(canonical, escapedSeparator, "\U00002028", 1),
		"lone surrogate":                       strings.Replace(canonical, escapedSeparator, `\ud800`, 1),
		"not JSON":                             "{",
	}
	for name, body := range invalid {
		t.Run(name, func(t *testing.T) {
			if status, _ := send(body); status != http.StatusBadRequest {
				t.Errorf("body %s got status %d", body, status)
			}
		})
	}
}
