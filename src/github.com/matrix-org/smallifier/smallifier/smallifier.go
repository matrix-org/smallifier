// smallifier is a basic link-shortener.
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

	log "github.com/Sirupsen/logrus"
	_ "github.com/mattn/go-sqlite3"
)

// SmallifierRequest is the JSON-encoded POST-body of an HTTP request to generate a short link.
type SmallifierRequest struct {
	// LongURL is the link to be shortened.
	LongURL string `json:"long_url"`
	Secret  string `json:"secret"`
}

// SmallifierResponse is the JSON-encoded POST-body of the response to a request to generate a short link.
type SmallifierResponse struct {
	// ShortURL is the generated short-link.
	ShortURL string `json:"short_url"`
}

type Smallifier struct {
	Base   url.URL
	DB     *sql.DB
	Secret string

	randomErrorCount uint64
	authErrorCount   uint64
}

// LookupHandler is an http.HandlerFunc which looks up a short link and either 302s to it, or 404s.
func (s *Smallifier) LookupHandler(w http.ResponseWriter, req *http.Request) {
	setHeaders(w)

	if !strings.HasPrefix(req.URL.Path, s.Base.Path) {
		w.WriteHeader(404)
		return
	}
	shortPath := req.URL.Path[len(s.Base.Path):]
	row := s.DB.QueryRow("SELECT long_url FROM links WHERE short_path = $1", shortPath)
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
func (s *Smallifier) CreateHandler(w http.ResponseWriter, req *http.Request) {
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

	if jsonReq.Secret != s.Secret {
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

	id, err := s.generateShortPath(jsonReq.LongURL)
	if err != nil {
		w.WriteHeader(500)
		io.WriteString(w, err.Error())
		return
	}

	enc := json.NewEncoder(w)
	enc.Encode(SmallifierResponse{s.Base.String() + id})
}

// RandomErrors gets a count of the number of times that we were unable to generate a random number.
// In normal operating conditions, this should always return 0.
// This being non-zero likely indicates the OS is having trouble generating randomness, which is really bad.
func (s *Smallifier) RandomErrors() float64 {
	return float64(atomic.LoadUint64(&s.randomErrorCount))
}

// AuthErrors gets a count of attempts made to create links without proper auth.
func (s *Smallifier) AuthErrors() float64 {
	return float64(atomic.LoadUint64(&s.authErrorCount))
}

func (s *Smallifier) generateShortPath(link string) (string, error) {
	for i := 0; i < 30; i++ {
		buf := make([]byte, 6)
		if _, err := rand.Read(buf); err != nil {
			atomic.AddUint64(&s.randomErrorCount, 1)
			log.Fatal("Could not generate random numbers", err)
			return "", fmt.Errorf(`{"error": "random error"}`)
		}

		shortPath := base64.RawURLEncoding.EncodeToString(buf)

		_, err := s.DB.Exec("INSERT INTO links (short_path, long_url) VALUES ($1, $2)", shortPath, link)
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

func CreateTable(db *sql.DB) error {
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
