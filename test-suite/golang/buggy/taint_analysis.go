package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

type repository struct{}

func (repository) Where(query string, args ...interface{}) repository { return repository{} }
func (repository) Find(dest interface{}) error                        { return nil }

var searchHandler = func(w http.ResponseWriter, r *http.Request) {
	term := r.Form.Get("term")
	sql := "SELECT id FROM articles WHERE title LIKE '%" + term + "%'"
	db.Query(sql)
}

func render(w http.ResponseWriter, r *http.Request) {
	comment := r.FormValue("comment")
	html := fmt.Sprintf("<div>%s</div>", comment)
	fmt.Fprintf(w, html)
}

func queryUser(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("user")
	sql := "SELECT * FROM users WHERE username = '" + username + "'"
	db.Exec(sql)
}

func queryWithContext(conn *sql.Conn, r *http.Request) {
	tenant := r.Header.Get("X-Tenant")
	sql := fmt.Sprintf("SELECT id FROM accounts WHERE tenant = '%s'", tenant)
	conn.QueryContext(r.Context(), sql)
}

func queryDirectSource(tx *sql.Tx, r *http.Request) {
	tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE owner = '"+r.URL.Query().Get("owner")+"'")
}

func queryBuilder(repo repository, r *http.Request) error {
	filter := "email = '" + r.PostFormValue("email") + "'"
	return repo.Where(filter).Find(&[]string{})
}

func runCmd(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	exec.Command("sh", "-c", "ls "+path).Run()
}

func main() {}
