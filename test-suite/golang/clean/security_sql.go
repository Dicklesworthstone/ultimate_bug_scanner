package main

import (
    "context"
    "database/sql"
    "log"
    "net/http"
    "time"

    _ "github.com/mattn/go-sqlite3"
)

var client = &http.Client{Timeout: 5 * time.Second}

func secureHandler(w http.ResponseWriter, r *http.Request) {
    user := r.URL.Query().Get("user")

    db, _ := sql.Open("sqlite3", ":memory:")
    ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
    defer cancel()

    rows, _ := db.QueryContext(ctx, "SELECT * FROM accounts WHERE name = ?", user)
    defer rows.Close()

    req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com", nil)
    client.Do(req)

    log.Printf("looked up %s", user)
}

func main() {
    http.HandleFunc("/", secureHandler)
    http.ListenAndServe(":8080", nil)
}
