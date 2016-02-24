package smallifier

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

var (
	stubResponse = "Go go gadget lemurs"
	testSecret   = "Ringtails have stripy, stripy tails"
)

func TestRoundtrip(t *testing.T) {
	server, _, c := serve(t)
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
	resp, err := insecureClient().Post(serverBaseURL+"/_create", "application/json", strings.NewReader(`{
		"long_url": "`+toShorten+`",
		"secret": "`+testSecret+`"
	}`))
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
	server, _, c := serve(t)
	defer c()

	resp, err := insecureClient().Post(server.URL+"/_create", "application/json", strings.NewReader(`{
		"long_url": "http://lemurs.win",
		"secret": "`+testSecret+`"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Error("non-https link: want status code 400 got", resp.StatusCode)
	}
}

func TestNoSecret(t *testing.T) {
	server, smallifier, c := serve(t)
	defer c()

	resp, err := insecureClient().Post(server.URL+"/_create", "application/json", strings.NewReader(`{"long_url": "https://lemurs.win"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Error("no secret: want status code 401 got", resp.StatusCode)
	}
	if got := smallifier.AuthErrors(); got != 1 {
		t.Errorf("auth error count: want 1 got %f", got)
	}
}

func TestWrongSecret(t *testing.T) {
	server, smallifier, c := serve(t)
	defer c()

	resp, err := insecureClient().Post(server.URL+"/_create", "application/json", strings.NewReader(`{
		"long_url": "https://lemurs.win",
		"secret": "wrong`+testSecret+`"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Error("no secret: want status code 401 got", resp.StatusCode)
	}
	if got := smallifier.AuthErrors(); got != 1 {
		t.Errorf("auth error count: want 1 got %f", got)
	}
}

func serve(t *testing.T) (*httptest.Server, *Smallifier, func()) {
	dir, err := ioutil.TempDir("", "smallifier")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "smallifier.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateTable(db); err != nil {
		t.Fatal(err)
	}
	s := &Smallifier{
		DB:     db,
		Secret: testSecret,
	}

	m := &mux{s}
	server := httptest.NewTLSServer(m)
	u, _ := url.Parse(server.URL + "/")
	s.Base = *u
	return server, s, func() {
		server.Close()
		db.Close()
		os.RemoveAll(dir)
	}
}

type mux struct {
	s *Smallifier
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
