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
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	stubResponse = "Go go gadget lemurs"
	testSecret   = "Ringtails have stripy, stripy tails"
)

func TestRoundtrip(t *testing.T) {
	f := serve(t)
	defer f.Close()

	shortened := shorten(t, f.server.URL, f.server.URL+"/_stub")

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
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.ShortURL
}

func TestNonHTTPS(t *testing.T) {
	f := serve(t)
	defer f.Close()

	resp, err := insecureClient().Post(f.server.URL+"/_create", "application/json", strings.NewReader(`{
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

func TestTooLong(t *testing.T) {
	f := serve(t)
	defer f.Close()

	resp, err := insecureClient().Post(f.server.URL+"/_create", "application/json", strings.NewReader(`{
		"long_url": "https://lemurs.win/`+strings.Repeat("yestheydo", 100)+`",
		"secret": "`+testSecret+`"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Error("too long link: want status code 400 got", resp.StatusCode)
	}
}

func TestNoSecret(t *testing.T) {
	f := serve(t)
	defer f.Close()

	resp, err := insecureClient().Post(f.server.URL+"/_create", "application/json", strings.NewReader(`{"long_url": "https://lemurs.win"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Error("no secret: want status code 401 got", resp.StatusCode)
	}
	if got := f.smallifier.AuthErrors(); got != 1 {
		t.Errorf("auth error count: want 1 got %f", got)
	}
}

func TestWrongSecret(t *testing.T) {
	f := serve(t)
	defer f.Close()

	resp, err := insecureClient().Post(f.server.URL+"/_create", "application/json", strings.NewReader(`{
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
	if got := f.smallifier.AuthErrors(); got != 1 {
		t.Errorf("auth error count: want 1 got %f", got)
	}
}

func TestRecordsStats(t *testing.T) {
	f := serve(t)
	defer f.Close()

	shortened := shorten(t, f.server.URL, f.base+"/_stub")
	shortPath := shortened[len(f.base):]

	r := f.db.QueryRow(`SELECT create_ts FROM links WHERE short_path = $1`, shortPath)
	var createTS int64
	if err := r.Scan(&createTS); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if createTS > now || createTS < now-10 {
		t.Errorf("create TS: want roughly %d got %d", now, createTS)
	}

	assertFollowCount(f, shortPath, 0, "before following:")

	resp, err := insecureClient().Get(shortened)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if got := string(b); stubResponse != got {
		dump, _ := httputil.DumpResponse(resp, false)
		t.Errorf("wrong response; want %q got %q HTTP response: %s", stubResponse, got, dump)
	}

	assertFollowCount(f, shortPath, 1, "after following:")

}

func assertFollowCount(f fixture, shortPath string, want int64, msg string) {
	for atomic.LoadInt64(&f.smallifier.(*smallifier).pendingFollows) > 0 {
		runtime.Gosched()
	}

	r := f.db.QueryRow(`SELECT COUNT(*) FROM follows WHERE short_path = $1`, shortPath)
	var got int64
	if err := r.Scan(&got); err != nil {
		f.t.Fatal(msg, err)
	}
	if want != got {
		f.t.Errorf("%s follow count want: %d got: %d", msg, want, got)
	}
}

type fixture struct {
	t          *testing.T
	server     *httptest.Server
	smallifier Smallifier
	base       string
	db         *sql.DB
	dir        string
}

func (f *fixture) Close() {
	f.server.Close()
	f.db.Close()
	os.RemoveAll(f.dir)
}

func serve(t *testing.T) fixture {
	dir, err := ioutil.TempDir("", "smallifier")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "smallifier.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateTables(db); err != nil {
		t.Fatal(err)
	}

	m := &mux{nil}
	server := httptest.NewTLSServer(m)
	u, _ := url.Parse(server.URL + "/")

	smallifier := New(*u, db, testSecret, 256)
	m.s = smallifier
	return fixture{
		t,
		server,
		smallifier,
		u.String(),
		db,
		dir,
	}
}

type mux struct {
	s Smallifier
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
