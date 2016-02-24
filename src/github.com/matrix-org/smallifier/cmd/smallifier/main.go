// smallifier is a basic link-shortener.
// It exposes an HTTP interface to allow short links to be generated and followed.
package main

import (
	"database/sql"
	"flag"
	"net/http"
	"net/url"

	_ "github.com/mattn/go-sqlite3"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/matrix-org/smallifier/smallifier"
)

var (
	base        = flag.String("base-url", "", "Base URL for links, e.g. https://mtrx.to/")
	addr        = flag.String("addr", "", "Address to listen for matrix requests on")
	secret      = flag.String("secret", "", "Secret which must be passed to create requests")
	lengthLimit = flag.Int("length-limit", 256, "Length limit of URLs being shortened. <= 0 means no limit.")
	sqliteDB    = flag.String("sqlite-db", "smallifier.db", "Path to sqlite3 database for persistent storage")
)

func main() {
	flag.Parse()
	if *base == "" || *addr == "" || *secret == "" {
		panic("Must specify non-empty base-url, addr, and secret")
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

	if err := smallifier.CreateTables(db); err != nil {
		panic(err)
	}

	s := smallifier.New(*baseURL, db, *secret, *lengthLimit)

	prometheus.MustRegister(prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "random_error_count",
			Help: "Counts number of errors encountered when trying to generate secure random numbers",
		},
		s.RandomErrors))

	prometheus.MustRegister(prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "auth_error_count",
			Help: "Counts number of errors encountered because of missing or incorrect secrets",
		},
		s.AuthErrors))

	prometheus.MustRegister(prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "db_update_error_count",
			Help: "Counts number of errors encountered updating the database",
		},
		s.DBUpdateErrors))

	http.HandleFunc("/_create", s.CreateHandler)
	http.HandleFunc("/", s.LookupHandler)
	panic(http.ListenAndServe(*addr, nil))
}
