package webpanel

import (
	"crypto/subtle"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// HashPassword returns "sha256:<hex>" using username as salt.
func HashPassword(password, username string) string {
	sum := sha256.Sum256([]byte(username + ":" + password))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func verifyPassword(password, stored, username string) bool {
	if stored == "" || password == "" {
		return false
	}
	if len(stored) > 7 && stored[:7] == "sha256:" {
		want := stored[7:]
		got := HashPassword(password, username)
		if len(got) > 7 {
			got = got[7:]
		}
		if len(want) != len(got) {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
}

func authFailed(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="virlink web panel", charset="UTF-8"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
