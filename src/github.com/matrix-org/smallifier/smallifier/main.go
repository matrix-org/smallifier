// smallifier is a basic link-shortener.
// It exposes an HTTP interface to allow short links to be generated and followed.
package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	log "github.com/Sirupsen/logrus"
	_ "github.com/mattn/go-sqlite3"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	base     = flag.String("base-url", "", "Base URL for links, e.g. https://mtrx.to/")
	addr     = flag.String("addr", "", "Address to listen for matrix requests on")
	sqliteDB = flag.String("sqlite-db", "smallifier.db", "Path to sqlite3 database for persistent storage")
)

func main() {
	flag.Parse()
	if *base == "" || *addr == "" {
		panic("Must specify base-url and addr")
	}
	baseURL, err := url.Parse(*base)
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("sqlite3", *sqliteDB)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if err := createTable(db); err != nil {
		panic(err)
	}

	s := &smallifier{
		base: *baseURL,
		db:   db,
	}

	prometheus.MustRegister(prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "random_error_count",
			Help: "Counts number of errors encountered when trying to generate secure random numbers",
		},
		s.RandomErrors))

	http.HandleFunc("/_create", s.CreateHandler)
	http.HandleFunc("/", s.LookupHandler)
	panic(http.ListenAndServe(*addr, nil))
}

// SmallifierRequest is the JSON-encoded POST-body of an HTTP request to generate a short link.
type SmallifierRequest struct {
	// LongURL is the link to be shortened.
	LongURL string `json:"long_url"`
}

// SmallifierResponse is the JSON-encoded POST-body of the response to a request to generate a short link.
type SmallifierResponse struct {
	// ShortURL is the generated short-link.
	ShortURL string `json:"short_url"`
}

type smallifier struct {
	base             url.URL
	db               *sql.DB
	randomErrorCount uint64
}

// LookupHandler is an http.HandlerFunc which looks up a short link and either 302s to it, or 404s.
func (s *smallifier) LookupHandler(w http.ResponseWriter, req *http.Request) {
	setHeaders(w)

	if !strings.HasPrefix(req.URL.Path, s.base.Path) {
		w.WriteHeader(404)
		return
	}
	shortPath := req.URL.Path[len(s.base.Path):]
	row := s.db.QueryRow("SELECT long_url FROM links WHERE short_path = $1", shortPath)
	var link string
	err := row.Scan(&link)
	if err == nil {
		w.Header().Set("Location", link)
		w.WriteHeader(302)
		return
	}
	if err == sql.ErrNoRows {
		w.WriteHeader(404)
		io.WriteString(w, `{"error": "link not found"}`)
		return
	}
	log.Error("Unknown DB error: ", err)
	w.WriteHeader(500)
	io.WriteString(w, `{"error": "internal server error"}`)
}

// CreateHandler is an http.HandlerFunc which creates a shortlink as a JSON-encoded SmallifierRequest in the request body and returns it as a JSON-encoded SmallifierResponse.
func (s *smallifier) CreateHandler(w http.ResponseWriter, req *http.Request) {
	setHeaders(w)

	defer req.Body.Close()
	dec := json.NewDecoder(req.Body)
	var jsonReq SmallifierRequest
	if err := dec.Decode(&jsonReq); err != nil {
		log.Error("Got bad json: ", err)
		w.WriteHeader(400)
		io.WriteString(w, `{"error": "error decoding json"}`)
		return
	}

	if !strings.HasPrefix(jsonReq.LongURL, "https://") {
		log.WithField("url", jsonReq.LongURL).Error("Refusing to linkify non-https link")
		w.WriteHeader(400)
		io.WriteString(w, `{"error": "Links must start with https://"}`)
		return
	}

	id, err := s.generateShortPath(jsonReq.LongURL)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	enc := json.NewEncoder(w)
	enc.Encode(SmallifierResponse{s.base.String() + id})
}

// RandomErrors gets a count of the number of times that we were unable to generate a random number.
// In normal operating conditions, this should always return 0.
// This being non-zero likely indicates the OS is having trouble generating randomness, which is really bad.
func (s *smallifier) RandomErrors() float64 {
	return float64(atomic.LoadUint64(&s.randomErrorCount))
}

func (s *smallifier) generateShortPath(link string) (string, error) {
	for i := 0; i < 30; i++ {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			atomic.AddUint64(&s.randomErrorCount, 1)
			log.Fatal("Could not generate random numbers", err)
			return "", fmt.Errorf(`{"error": "random error"}`)
		}

		shortPath := base64.RawURLEncoding.EncodeToString(buf)

		_, err := s.db.Exec("INSERT INTO links (short_path, long_url) VALUES ($1, $2)", shortPath, link)
		if err == nil {
			return shortPath, nil
		}
		log.WithField("error", err).Error("Error saving link")
	}
	return "", fmt.Errorf(`{"error": "could not generate link"}`)
}

// setHeaders sets the "Content-Type" to "application/json" and sets CORS
// headers so that arbitrary sites can use the APIs.
func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
}

func createTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS links(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		short_path TEXT NOT NULL UNIQUE,
		long_url TEXT NOT NULL
	)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS links_short_path on links(short_path)`)
	return err
}
