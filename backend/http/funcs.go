package http

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes obj to the HTTP response as JSON, with the status. It writes the status and the
// Content-Type header itself, since headers can't change once the status is written, so any other
// headers have to be set before calling it. If obj can't be encoded, it writes a 500 instead.
func WriteJSON(w http.ResponseWriter, status int, obj any) error {
	body, err := json.Marshal(obj)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(body)
	return err
}
