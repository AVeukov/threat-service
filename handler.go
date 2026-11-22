package main

import (
	"encoding/json"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
)

const maxBodySize = 1024 * 1024

type Handler struct {
	store *Store
}

func NewHandler(store *Store) http.Handler {
	h := &Handler{store: store}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", h.create)
	mux.HandleFunc("/info/{md5}", h.byMD5)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Route not found", "")
	})
	return mux
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}
	var request CreateRequest
	if !readJSON(w, r, &request) {
		return
	}
	if !md5Pattern.MatchString(request.MD5) {
		writeError(w, http.StatusBadRequest, "Invalid MD5", "Expected 32 hexadecimal characters")
		return
	}
	if err := request.ThreatFields.normalizeAndValidate(); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid threat", err.Error())
		return
	}
	md5 := strings.ToLower(request.MD5)
	threat, created := h.store.Create(md5, request.ThreatFields)
	if !created {
		writeError(w, http.StatusConflict, "Threat already exists", "")
		return
	}
	w.Header().Set("Location", "/info/"+md5)
	writeJSON(w, http.StatusCreated, threat)
}

func (h *Handler) byMD5(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
		return
	}
	md5 := r.PathValue("md5")
	if !md5Pattern.MatchString(md5) {
		writeError(w, http.StatusBadRequest, "Invalid MD5", "Expected 32 hexadecimal characters")
		return
	}
	md5 = strings.ToLower(md5)
	if r.Method == http.MethodGet {
		threat, found := h.store.Get(md5)
		if !found {
			writeError(w, http.StatusNotFound, "Threat not found", "")
			return
		}
		writeJSON(w, http.StatusOK, threat)
		return
	}
	var fields ThreatFields
	if !readJSON(w, r, &fields) {
		return
	}
	if err := fields.normalizeAndValidate(); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid threat", err.Error())
		return
	}
	threat, found := h.store.Update(md5, fields)
	if !found {
		writeError(w, http.StatusNotFound, "Threat not found", "")
		return
	}
	writeJSON(w, http.StatusOK, threat)
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusBadRequest, "Invalid Content-Type", "Expected application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON", "Check fields, types and the 1 MiB body limit")
		return false
	}
	var extraValue any
	if err := decoder.Decode(&extraValue); err != io.EOF {
		writeError(w, http.StatusBadRequest, "Invalid JSON", "Expected exactly one JSON object within 1 MiB")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	writeJSON(w, status, ErrorResponse{Message: message, Details: details})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		log.Printf("encode response: %v", err)
		status = http.StatusInternalServerError
		data = []byte(`{"message":"Internal server error"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		log.Printf("write response: %v", err)
	}
}
