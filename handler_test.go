package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func TestThreatLifecycle(t *testing.T) {
	server := httptest.NewServer(NewHandler(NewStore()))
	defer server.Close()
	request := func(method, path, body string, wantStatus int) Threat {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, wantStatus, data)
		}
		if resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("unexpected content type: %s", resp.Header.Get("Content-Type"))
		}
		if wantStatus >= 400 {
			var response ErrorResponse
			if err := json.Unmarshal(data, &response); err != nil || response.Message == "" {
				t.Fatalf("invalid error response: %s", data)
			}
			return Threat{}
		}
		if wantStatus == http.StatusCreated && resp.Header.Get("Location") != "/info/"+testMD5 {
			t.Fatalf("unexpected Location: %s", resp.Header.Get("Location"))
		}
		var threat Threat
		if err := json.Unmarshal(data, &threat); err != nil {
			t.Fatal(err)
		}
		return threat
	}

	path := "/info/" + testMD5
	request("GET", path, "", 404)
	request("PUT", path, `{"name":"Missing"}`, 404)
	body := `{"md5":"` + strings.ToUpper(testMD5) + `","name":" Trojan ","description":"Steals passwords","severity":"high"}`
	created := request("POST", "/info", body, 201)
	if created.MD5 != testMD5 || created.Name != "Trojan" || created.Description != "Steals passwords" || created.Severity != "high" {
		t.Fatalf("unexpected threat: %+v", created)
	}
	if created.CreatedAt.IsZero() || !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("invalid creation timestamps: %+v", created)
	}
	request("POST", "/info", strings.ReplaceAll(body, strings.ToUpper(testMD5), testMD5), 409)
	if got := request("GET", "/info/"+strings.ToUpper(testMD5), "", 200); got != created {
		t.Fatalf("GET = %+v, want %+v", got, created)
	}
	request("PUT", path, `{"name":""}`, 400)
	if got := request("GET", path, "", 200); got != created {
		t.Fatal("invalid update changed stored data")
	}
	updated := request("PUT", "/info/"+strings.ToUpper(testMD5), `{"name":"Updated"}`, 200)
	if updated.Name != "Updated" || updated.Description != "" || updated.Severity != "unknown" || updated.MD5 != testMD5 {
		t.Fatalf("PUT did not replace fields: %+v", updated)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) || updated.UpdatedAt.Before(created.UpdatedAt) {
		t.Fatalf("invalid update timestamps: %+v", updated)
	}
	if got := request("GET", path, "", 200); got != updated {
		t.Fatalf("update was not saved: %+v", got)
	}
}

func TestInvalidRequests(t *testing.T) {
	valid := `{"md5":"` + testMD5 + `","name":"Trojan"}`
	tests := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		status      int
	}{
		{"bad path MD5", "GET", "/info/bad", "", "", 400},
		{"bad PUT MD5", "PUT", "/info/bad", `{"name":"Trojan"}`, "application/json", 400},
		{"bad body MD5", "POST", "/info", `{"md5":"bad","name":"Trojan"}`, "application/json", 400},
		{"missing MD5", "POST", "/info", `{"name":"Trojan"}`, "application/json", 400},
		{"missing name", "POST", "/info", `{"md5":"` + testMD5 + `"}`, "application/json", 400},
		{"empty body", "POST", "/info", "", "application/json", 400},
		{"broken JSON", "POST", "/info", `{"md5":`, "application/json", 400},
		{"wrong type", "POST", "/info", `{"md5":123,"name":"Trojan"}`, "application/json", 400},
		{"null body", "POST", "/info", "null", "application/json", 400},
		{"array body", "POST", "/info", "[]", "application/json", 400},
		{"unknown field", "POST", "/info", strings.TrimSuffix(valid, "}") + `,"extra":true}`, "application/json", 400},
		{"two objects", "POST", "/info", valid + `{}`, "application/json", 400},
		{"trailing garbage", "POST", "/info", valid + `!`, "application/json", 400},
		{"bad severity", "POST", "/info", strings.TrimSuffix(valid, "}") + `,"severity":"bad"}`, "application/json", 400},
		{"large body", "POST", "/info", `{"name":"` + strings.Repeat("a", maxBodySize) + `"}`, "application/json", 400},
		{"large trailing whitespace", "POST", "/info", valid + strings.Repeat(" ", maxBodySize), "application/json", 400},
		{"missing content type", "POST", "/info", valid, "", 400},
		{"wrong content type", "POST", "/info", valid, "text/plain", 400},
		{"changing MD5", "PUT", "/info/" + testMD5, valid, "application/json", 400},
		{"unknown route", "GET", "/missing", "", "", 404},
		{"wrong collection method", "GET", "/info", "", "", 405},
		{"wrong item method", "DELETE", "/info/" + testMD5, "", "", 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			response := httptest.NewRecorder()
			NewHandler(store).ServeHTTP(response, req)
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, tt.status, response.Body.String())
			}
			var apiError ErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &apiError); err != nil || apiError.Message == "" {
				t.Fatalf("invalid error response: %s", response.Body.String())
			}
			if tt.status == 405 && response.Header().Get("Allow") == "" {
				t.Fatal("missing Allow header")
			}
			if len(store.threats) != 0 {
				t.Fatal("invalid request created a record")
			}
		})
	}
}

func TestConcurrentRequests(t *testing.T) {
	handler := NewHandler(NewStore())
	const count = 30
	statuses := make(chan int, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := `{"md5":"` + testMD5 + `","name":"Trojan"}`
			req := httptest.NewRequest("POST", "/info", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			statuses <- response.Code
			for _, method := range []string{"PUT", "GET"} {
				req := httptest.NewRequest(method, "/info/"+testMD5, strings.NewReader(`{"name":"Updated"}`))
				req.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if response.Code != 200 {
					t.Errorf("%s: status = %d", method, response.Code)
				}
			}
		}()
	}
	wg.Wait()
	close(statuses)
	created := 0
	for status := range statuses {
		switch status {
		case 201:
			created++
		case 409:
		default:
			t.Errorf("unexpected create status: %d", status)
		}
	}
	if created != 1 {
		t.Fatalf("created %d records, want exactly one", created)
	}
}
