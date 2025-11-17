package main

import (
    "context"
    "database/sql"
    "log"
    "net/http"
    "os/exec"

    _ "github.com/mattn/go-sqlite3"
)

var client = &http.Client{} // no timeout

func insecureHandler(w http.ResponseWriter, r *http.Request) {
    user := r.URL.Query().Get("user")
    query := "SELECT * FROM accounts WHERE name = '" + user + "'"

    db, _ := sql.Open("sqlite3", ":memory:")
    rows, _ := db.Query(query) // SQL injection
    defer rows.Close()

    cmd := exec.Command("sh", "-c", "ls "+user)
    cmd.Run() // command injection

    req, _ := http.NewRequest("GET", "https://example.com", nil)
    client.Do(req) // missing Timeout

    log.Println("insecure", user)
}

func main() {
    http.HandleFunc("/", insecureHandler)
    http.ListenAndServe(":8080", nil)
}
