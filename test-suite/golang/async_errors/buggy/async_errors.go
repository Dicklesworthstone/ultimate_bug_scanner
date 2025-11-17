package main

import (
    "fmt"
    "net/http"
)

func fireAndForget(urls []string) {
    for _, url := range urls {
        go func(u string) {
            resp, _ := http.Get(u)
            fmt.Println("status", resp.Status)
        }(url)
    }
}

func main() {
    fireAndForget([]string{"https://example.com"})
}
