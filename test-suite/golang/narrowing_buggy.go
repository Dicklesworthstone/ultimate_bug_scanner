package golang

import (
	"fmt"
	"log"
	"os"
)

// User is a minimal record used by the narrowing fixtures.
type User struct {
	Name string
	Age  int
}

// LookupUser returns nil for unknown ids.
func LookupUser(id string) *User {
	if id == "missing" {
		return nil
	}
	return &User{Name: id, Age: 42}
}

// readConfig logs a failed config read and falls through, then propagates the
// partially-built companion value.
func readConfig(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("config read failed, continuing: %v", err)
	}
	return data, err
}

// fallthroughErrUse keeps consuming the companion after a log-only guard.
func fallthroughErrUse(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("using partial contents: %v", err)
	}
	fmt.Println(len(data))
}

// wrappedErrUse logs the failure and still propagates the stale error.
func wrappedErrUse(path string) error {
	_, err := os.ReadFile(path)
	if err != nil {
		log.Printf("config unavailable: %v", err)
	}
	return fmt.Errorf("load config: %w", err)
}

// derefAfterNilGuard falls through a nil check and dereferences anyway.
func derefAfterNilGuard(id string) string {
	user := LookupUser(id)
	if user == nil {
		log.Println("unknown user, continuing anyway")
	}
	return user.Name
}
