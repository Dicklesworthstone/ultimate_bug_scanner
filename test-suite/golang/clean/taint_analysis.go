package main

import (
	"context"
	"database/sql"
	"fmt"
	"html"
	"net/http"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

type repository struct{}

func (repository) Where(query string, args ...interface{}) repository { return repository{} }
func (repository) Find(dest interface{}) error                        { return nil }

var searchHandler = func(w http.ResponseWriter, r *http.Request) {
	term := r.Form.Get("term")
	db.Query("SELECT id FROM articles WHERE title LIKE ?", "%"+term+"%")
}

func render(w http.ResponseWriter, r *http.Request) {
	comment := html.EscapeString(r.FormValue("comment"))
	htmlBody := fmt.Sprintf("<div>%s</div>", comment)
	fmt.Fprint(w, htmlBody)
}

func queryUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("user")
	db.Exec("SELECT * FROM users WHERE username = ?", username)
}

func queryWithContext(ctx context.Context, conn *sql.Conn, r *http.Request) {
	tenant := r.Header.Get("X-Tenant")
	conn.QueryContext(ctx, "SELECT id FROM accounts WHERE tenant = ?", tenant)
}

func queryDirectSource(tx *sql.Tx, r *http.Request) {
	tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE owner = ?", r.URL.Query().Get("owner"))
}

func queryBuilder(repo repository, r *http.Request) error {
	email := r.PostFormValue("email")
	return repo.Where("email = ?", email).Find(&[]string{})
}

func runCmd(w http.ResponseWriter, r *http.Request) {
	path := filepath.Clean(r.FormValue("path"))
	exec.Command("ls", path).Run()
}

func main() {}
