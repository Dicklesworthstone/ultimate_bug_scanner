package security

import (
	"encoding/json"
	"io"
	"net/http"
)

const maxBodyBytes int64 = 1 << 20

type uploadPayload struct {
	Name string `json:"name"`
}

type aliasCleaner struct{}

func importPayload(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	return io.ReadAll(r.Body)
}

func readLimitedUpload(r *http.Request) ([]byte, error) {
	limited := io.LimitReader(r.Body, maxBodyBytes)
	return io.ReadAll(limited)
}

func readLimitedAlias(r *http.Request) ([]byte, error) {
	limitedBody := io.LimitReader(r.Body, maxBodyBytes)
	return io.ReadAll(limitedBody)
}

func decodePayload(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var payload uploadPayload
	return json.NewDecoder(r.Body).Decode(&payload)
}

func decodeLimitedPayload(r *http.Request) error {
	limited := io.LimitReader(r.Body, maxBodyBytes)
	var payload uploadPayload
	return json.NewDecoder(limited).Decode(&payload)
}

func decodeLimitedAlias(r *http.Request) error {
	body := io.LimitReader(r.Body, maxBodyBytes)
	var payload uploadPayload
	decoder := json.NewDecoder(body)
	return decoder.Decode(&payload)
}

func (aliasCleaner) rememberBodyAlias(r *http.Request) io.ReadCloser {
	body := r.Body
	return body
}

func (aliasCleaner) readNonRequestBody(body io.Reader) ([]byte, error) {
	return io.ReadAll(body)
}
