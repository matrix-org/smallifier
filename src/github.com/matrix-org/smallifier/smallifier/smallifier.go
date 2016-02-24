// Package smallifier is a basic link-shortener.
// It supplies HTTP handlers to allow short links to be generated and followed.
package smallifier

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/Sirupsen/logrus"
)

// Request is the JSON-encoded POST-body of an HTTP request to generate a short link.
type Request struct {
	// LongURL is the link to be shortened.
	LongURL string `json:"long_url"`
	Secret  string `json:"secret"`
}

// Response is the JSON-encoded POST-body of the response to a request to generate a short link.
type Response struct {
	// ShortURL is the generated short-link.
	ShortURL string `json:"short_url"`
}

// Smallifier implements a basic link shortener.
type Smallifier interface {
	// HTTP handler which accepts a JSON object containing a long_url and secret, and returns a JSON object with a short_url.
	CreateHandler(w http.ResponseWriter, req *http.Request)
	// HTTP handler which redirects to the long URL for the requested path.
	LookupHandler(w http.ResponseWriter, req *http.Request)

	// RandomErrors gets a count of the number of times that we were unable to generate a random number.
	// In normal operating conditions, this should always return 0.
	// This being non-zero likely indicates the OS is having trouble generating randomness, which is really bad.
	RandomErrors() float64
	// AuthErrors gets a count of attempts made to create links without proper auth.
	AuthErrors() float64
	// DBUpdateErrors gets a count of attempts made to update the database which failed.
	DBUpdateErrors() float64
}

// New makes a new Smallifier.
func New(base url.URL, db *sql.DB, secret string) Smallifier {
	s := &smallifier{
		base:        base,
		db:          db,
		secret:      secret,
		follows:     make(chan follow, 1024*1024),
	}

	go func() {
		for f := range s.follows {
			if _, err := s.db.Exec(`INSERT INTO follows (short_path, ts, ip, forwarded_for) VALUES ($1, $2, $3, $4)`, f.shortPath, f.timestamp, f.ip, f.forwardedFor); err != nil {
				log.WithField("err", err).Error("Error inserting follow")
				atomic.AddUint64(&s.dbUpdateErrorCount, 1)
			}
			atomic.AddInt64(&s.pendingFollows, -1)
		}
	}()

	return s
}

type smallifier struct {
	base        url.URL
	db          *sql.DB
	secret      string

	follows        chan follow
	pendingFollows int64

	randomErrorCount   uint64
	authErrorCount     uint64
	dbUpdateErrorCount uint64
}

type follow struct {
	shortPath    string
	timestamp    int64
	ip           string
	forwardedFor string
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

		atomic.AddInt64(&s.pendingFollows, 1)
		s.follows <- follow{
			shortPath:    shortPath,
			timestamp:    time.Now().Unix(),
			ip:           req.RemoteAddr,
			forwardedFor: req.Header.Get("X-Forwarded-For"),
		}

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

// CreateHandler is an http.HandlerFunc which creates a shortlink as a JSON-encoded Request in the request body and returns it as a JSON-encoded Response.
func (s *smallifier) CreateHandler(w http.ResponseWriter, req *http.Request) {
	setHeaders(w)

	defer req.Body.Close()
	dec := json.NewDecoder(req.Body)
	var jsonReq Request
	if err := dec.Decode(&jsonReq); err != nil {
		log.Error("Got bad json: ", err)
		w.WriteHeader(400)
		io.WriteString(w, `{"error": "error decoding json"}`)
		return
	}

	if jsonReq.Secret != s.secret {
		atomic.AddUint64(&s.authErrorCount, 1)
		log.WithField("bad_secret", jsonReq.Secret).Error("Refusing to linkify with wrong secret")
		w.WriteHeader(401)
		io.WriteString(w, `{"error": "Must specify correct secret"}`)
		return
	}

	if !strings.HasPrefix(jsonReq.LongURL, "https://") {
		log.WithField("url", jsonReq.LongURL).Error("Refusing to linkify non-https link")
		w.WriteHeader(400)
		io.WriteString(w, `{"error": "Links must start with https://"}`)
		return
	}

	id, err := s.generateShortPath(jsonReq.LongURL, req.RemoteAddr, req.Header.Get("X-Forwarded-For"))
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	enc := json.NewEncoder(w)
	enc.Encode(Response{s.base.String() + id})
}

// RandomErrors gets a count of the number of times that we were unable to generate a random number.
// In normal operating conditions, this should always return 0.
// This being non-zero likely indicates the OS is having trouble generating randomness, which is really bad.
func (s *smallifier) RandomErrors() float64 {
	return float64(atomic.LoadUint64(&s.randomErrorCount))
}

// AuthErrors gets a count of attempts made to create links without proper auth.
func (s *smallifier) AuthErrors() float64 {
	return float64(atomic.LoadUint64(&s.authErrorCount))
}

// DBUpdateErrors gets a count of attempts made to update the database which failed.
func (s *smallifier) DBUpdateErrors() float64 {
	return float64(atomic.LoadUint64(&s.dbUpdateErrorCount))
}

func (s *smallifier) generateShortPath(link, ip, forwardedFor string) (string, error) {
	for i := 0; i < 30; i++ {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			atomic.AddUint64(&s.randomErrorCount, 1)
			log.Fatal("Could not generate random numbers", err)
			return "", fmt.Errorf(`{"error": "random error"}`)
		}

		shortPath := base64.RawURLEncoding.EncodeToString(buf)

		_, err := s.db.Exec("INSERT INTO links (short_path, long_url, create_ts, create_ip, create_forwarded_for) VALUES ($1, $2, $3, $4, $5)", shortPath, link, time.Now().Unix(), ip, forwardedFor)
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

// CreateTables creates the necessary database tables in db if they are absent.
func CreateTables(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS links(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		short_path TEXT NOT NULL UNIQUE,
		long_url TEXT NOT NULL,
		create_ts BIGINT NOT NULL,
		create_ip TEXT NOT NULL,
		create_forwarded_for TEXT
	)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS links_short_path on links(short_path)`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS follows(
		id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		short_path TEXT NOT NULL,
		ts BIGINT NOT NULL,
		ip TEXT NOT NULL,
		forwarded_for TEXT
	)`)
	return err
}
