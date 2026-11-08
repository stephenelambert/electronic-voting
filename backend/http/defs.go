package http

import (
	"bytes"
	"log"
	"net/http"
	"time"
)

// allow 5 seconds of time drift between client and server
const allowedTimeDrift int64 = 5000

// maxRequestBodyBytes is the largest request body BodyToCtx will read (1 MiB)
const maxRequestBodyBytes int64 = 1 << 20

// finishTimeout is the longest TxToCtx waits to commit or roll back a request's transaction. A
// client disconnecting doesn't stop either, so they need their own limit, which is well under the
// server's 15-second WriteTimeout.
const finishTimeout = 5 * time.Second

// ResponseWriterWrapper holds a handler's response, so TxToCtx can send it only once the request's
// transaction has committed. It deliberately has no Flush or Unwrap method, so nothing can send
// part of the response early.
type ResponseWriterWrapper struct {
	header http.Header

	// status is the HTTP status code written, or 0 if none has been
	status int

	body bytes.Buffer
}

// newResponseWriterWrapper returns a wrapper that isn't holding a response yet
func newResponseWriterWrapper() *ResponseWriterWrapper {
	return &ResponseWriterWrapper{
		header: http.Header{},
	}
}

// Header returns the headers of the held response
func (r *ResponseWriterWrapper) Header() http.Header {
	return r.header
}

// Write adds b to the held response's body. As in net/http, writing before WriteHeader means a
// status of 200.
func (r *ResponseWriterWrapper) Write(b []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.body.Write(b)
}

// WriteHeader saves the statusCode. As in net/http, only the first call counts.
func (r *ResponseWriterWrapper) WriteHeader(statusCode int) {
	if r.status == 0 {
		r.status = statusCode
	}
}

// Status returns the status written, or 200 (what net/http sends) if none has been
func (r *ResponseWriterWrapper) Status() int {
	if r.status == 0 {
		return http.StatusOK
	}

	return r.status
}

// send writes the held response to w
func (r *ResponseWriterWrapper) send(w http.ResponseWriter) {
	for key, values := range r.header {
		w.Header()[key] = values
	}

	w.WriteHeader(r.Status())
	if _, err := w.Write(r.body.Bytes()); err != nil {
		log.Printf("error writing response: %v", err)
	}
}
