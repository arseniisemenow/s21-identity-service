package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

// generateAPIKey returns 32 cryptographically random bytes, base64-stdencoded.
// Identical algorithm to the server's path so a key minted via the CLI
// authenticates the same way a key minted via POST /admin/keys would.
func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// hashAPIKey returns base64(sha256(plaintext)) — the value stored as the row's
// key_hash. Same encoding the server's middleware uses for lookup.
func hashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// printNewKeyBanner prints a one-shot reveal of a freshly-minted key. ANSI
// red is used only when stdout looks like a TTY; piped output stays plain so
// the value is easy to copy with `... | tr -d '\n' | xclip` or similar.
func printNewKeyBanner(name, scopes, plaintext string) {
	bold, red, reset := "", "", ""
	if isTerminal(os.Stdout) {
		bold, red, reset = "\033[1m", "\033[31m", "\033[0m"
	}
	fmt.Printf("\n%s%sKEY CREATED — copy this value NOW. It will NEVER be shown again.%s\n", bold, red, reset)
	fmt.Printf("  name:    %s\n", name)
	fmt.Printf("  scopes:  %s\n", scopes)
	fmt.Printf("  key:     %s\n\n", plaintext)
	fmt.Println("Put the key into the receiving service's env (e.g. IDENTITY_API_KEY=... in terraform.tfvars), then re-deploy.")
}

// isTerminal is a deliberately conservative TTY check — no cgo, no external
// deps. Pipes and redirects to files report not-a-terminal, suppressing the
// ANSI sequences so the captured plaintext stays clean.
func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
