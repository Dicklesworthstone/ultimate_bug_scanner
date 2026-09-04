package golang

import (
	"errors"
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

// fullErrGuard returns immediately, so the companion is only used when err is nil.
func fullErrGuard(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// nilCheckedEarly exits on the nil case, so the deref below is safe.
func nilCheckedEarly(id string) (string, error) {
	user := LookupUser(id)
	if user == nil {
		return "", errors.New("unknown user")
	}
	return user.Name, nil
}

// recheckedErr rescues a logging guard with an exiting re-check.
func recheckedErr(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("read failed, falling back: %v", err)
	}
	if err != nil {
		data = defaultConfig()
	}
	return data, err
}

// fallbackAfterPartialGuard overwrites the companion before using it.
func fallbackAfterPartialGuard(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("read failed, using defaults: %v", err)
	}
	data = defaultConfig()
	return data
}

// scopedErr keeps err scoped to the init statement, so nothing uses it after.
func scopedErr(path string) bool {
	if _, err := os.Stat(path); err != nil {
		log.Printf("stat failed: %v", err)
	}
	return false
}

// guardedDeref dereferences only inside the non-nil branch.
func guardedDeref(id string) string {
	user := LookupUser(id)
	if user != nil {
		return user.Name
	}
	return "anonymous"
}

// loggingGuardWithoutUse logs the error and never touches the value again.
func loggingGuardWithoutUse(path string) {
	_, err := os.ReadFile(path)
	if err != nil {
		log.Printf("config unavailable: %v", err)
	}
	fmt.Println("config load attempted")
}

func defaultConfig() []byte {
	return []byte("mode=production\n")
}
