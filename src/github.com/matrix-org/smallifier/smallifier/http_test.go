package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var stubResponse = "Go go gadget lemurs"

func TestRoundtrip(t *testing.T) {
	server, c := serve(t)
	defer c()

	shortened := shorten(t, server.URL, server.URL+"/_stub")

	resp, err := insecureClient().Get(shortened)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if got := string(b); stubResponse != got {
		dump, _ := httputil.DumpResponse(resp, false)
		t.Errorf("wrong response; want %q got %q HTTP response: %s", stubResponse, got, dump)
	}
}

func shorten(t *testing.T, serverBaseURL, toShorten string) string {
	resp, err := insecureClient().Post(serverBaseURL+"/_create", "application/json", strings.NewReader(`{"long_url": "`+toShorten+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var r SmallifierResponse
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.ShortURL
}

func TestNonHTTPS(t *testing.T) {
	server, c := serve(t)
	defer c()

	resp, err := insecureClient().Post(server.URL+"/_create", "application/json", strings.NewReader(`{"long_url": "http://lemurs.win"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Error("non-https link: want status code 400 got", resp.StatusCode)
	}
}

func serve(t *testing.T) (*httptest.Server, func()) {
	dir, err := ioutil.TempDir("", "smallifier")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "smallifier.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := createTable(db); err != nil {
		t.Fatal(err)
	}
	s := &smallifier{
		db: db,
	}

	m := &mux{s}
	server := httptest.NewTLSServer(m)
	u, _ := url.Parse(server.URL + "/")
	s.base = *u
	return server, func() {
		server.Close()
		db.Close()
		os.RemoveAll(dir)
	}
}

type mux struct {
	s *smallifier
}

func (m *mux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case "/_create":
		m.s.CreateHandler(w, req)
	case "/_stub":
		io.WriteString(w, stubResponse)
	default:
		m.s.LookupHandler(w, req)
	}
}

func insecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
