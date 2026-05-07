package buggy

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	_ "net/http/pprof"
	. "strings"
	"sort"
	"strings"
	"sync"
	"time"
)

func concurrencyCoverage(items []string, ch <-chan string, wg *sync.WaitGroup) {
	for _, item := range items {
		go processItem(item)
	}

	for i := range items {
		go func() {
			fmt.Println(i)
		}()
	}

	for i := 0; i < len(items); i++ {
		go func() {
			fmt.Println(i)
		}()
	}

	for _, item := range items {
		defer processItem(item)
	}

	select {
	case <-ch:
		fmt.Println("received")
	}

	recover()
	panic("rule-pack coverage")

	wg.Add(1)
	if len(items) == 0 {
		return
	}
	wg.Done()
}

func contextCoverage(parent context.Context, cond bool, err error) {
	context.TODO()

	ctx, cancel := context.WithCancel(parent)
	if cond {
		defer cancel()
	}
	_ = ctx

	defer cancel()
	if err != nil {
		return
	}
	processItem("after err")
	cancel()
}

func httpCoverage(w http.ResponseWriter, r *http.Request, url string, cond bool) error {
	_ = context.Background()

	http.Get(url)
	http.Post(url, "text/plain", strings.NewReader("body"))
	http.Head(url)
	http.DefaultClient.Do(r)
	http.NewRequest("GET", url, nil)
	exec.Command("curl", url)

	client := &http.Client{}
	_ = client
	_ = http.Client{}
	_ = http.Transport{Proxy: http.ProxyFromEnvironment}
	_ = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	_ = tls.Config{}
	_ = http.Server{Addr: ":8080"}

	resp, err := http.Get(url)
	defer resp.Body.Close()
	if err != nil {
		return err
	}

	resp2, err := http.Head(url)
	if err != nil {
		return err
	}
	processItem("between response and close")
	defer resp2.Body.Close()

	resp3, err := client.Do(r)
	if err != nil {
		return err
	}
	_ = resp3

	w.Write([]byte("ignored responsewriter error"))
	fmt.Fprintf(w, "ignored fprintf error")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	if cond {
		return nil
	}
	return nil
}

func jsonCoverage(w http.ResponseWriter, r *http.Request) {
	var dst map[string]any
	json.NewDecoder(r.Body).Decode(&dst)

	dec := json.NewDecoder(r.Body)
	dec.Decode(&dst)
}

func fileCoverage(path string, payload []byte) error {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return err
	}

	created, err := os.Create(path)
	if err != nil {
		return err
	}
	created.Close()
	os.Remove(path)

	ioutil.ReadAll(strings.NewReader("legacy"))
	io.WriteString(created, string(payload))
	return nil
}

func sqlCoverage(ctx context.Context, db *sql.DB, queryPart string) error {
	rows, err := db.Query("SELECT * FROM users")
	defer rows.Close()
	if err != nil {
		return err
	}

	rows2, err := db.QueryContext(ctx, "SELECT * FROM users")
	if err != nil {
		return err
	}
	processItem("between rows and close")
	defer rows2.Close()

	rows3, err := db.Query("SELECT * FROM users WHERE name = " + queryPart)
	if err != nil {
		return err
	}
	for rows3.Next() {
		processItem("row")
	}

	tx, err := db.Begin()
	defer tx.Rollback()
	if err != nil {
		return err
	}

	tx2, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	processItem("between tx and rollback")
	defer tx2.Rollback()

	tx3, err := db.Begin()
	if err != nil {
		return err
	}
	tx3.Commit()

	db.Exec("DELETE FROM sessions WHERE id = " + queryPart)
	return nil
}

func ignoredErrorsCoverage(w io.Writer, tmpl *template.Template, data any, path string) {
	n, _ := w.Write([]byte("ignored write error"))
	_ = n
	fmt.Fprintf(w, "ignored fprintf %v", data)
	tmpl.Execute(w, data)

	err := fmt.Errorf("lost wrapped error: %v", data)
	if err != nil {
	}
	if err != nil {
		return
	}

	os.Remove(path)
}

func commandCoverage(commandLine string) {
	exec.Command("pgrep", commandLine)
	exec.Command("grep", strings.Fields(commandLine)...)
	exec.Command("sh", "-c", commandLine)
}

func timeCoverage(cond bool) {
	time.Tick(time.Second)

	for cond {
		<-time.After(time.Second)
		break
	}

	timer := time.NewTimer(time.Second)
	timer.Stop()

	ticker := time.NewTicker(time.Second)
	_ = ticker
}

func collectionCoverage(items []int, contentType string) {
	sort.Slice(items, func(i, j int) bool {
		return items[i] < items[j]
	})

	strings.HasPrefix(contentType, "application/json")
	HasPrefix(contentType, "application/json")
}

func processItem(value string) {
	fmt.Println(value)
}
