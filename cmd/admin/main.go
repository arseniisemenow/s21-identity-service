// Command admin is the identity-service operator CLI. It manages API keys in
// the identity service's YDB database directly (no HTTP), so the operator
// doesn't need any pre-existing API key to bootstrap the system.
//
// Auth: shells out to `yc iam create-token` and uses the returned token to
// authenticate to YDB.
//
// Subcommands:
//
//	create-key   Mint a fresh key. Plaintext is shown ONCE and never recoverable.
//	list-keys    Tabulate every key (active + revoked) with metadata.
//	revoke-key   Soft-delete an active key by name.
//
// Required env: YDB_ENDPOINT (the same value the identity-service function uses).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ydb-platform/ydb-go-sdk/v3"

	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store"
	"github.com/arseniisemenow/ttbot-repo-placeholder-3/pkg/store/ydbstore"
)

const usage = `Identity-service admin CLI.

Usage:
  admin <command> [flags]

Commands:
  create-key   Mint a new API key.
  list-keys    Show every key (active + revoked).
  revoke-key   Revoke an active key by name.

Environment:
  YDB_ENDPOINT   Connection string of the identity-service YDB (required).
                 Typical value:
                   grpcs://ydb.serverless.yandexcloud.net:2135/?database=/ru-central1/<cloud>/<db>

Auth: shells out to ` + "`yc iam create-token`" + ` to obtain an IAM token. Configure
the yc CLI (yc init) before running.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "create-key":
		err = runCreate(args)
	case "list-keys":
		err = runList(args)
	case "revoke-key":
		err = runRevoke(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// ------------ subcommands ------------

func runCreate(args []string) error {
	fs := flag.NewFlagSet("create-key", flag.ExitOnError)
	name := fs.String("name", "", "key name (required, 1–64 chars, [A-Za-z0-9_.-])")
	scopes := fs.String("scopes", "read", "scope set: read | write | read,write")
	createdBy := fs.Int64("created-by", 0, "telegram_id of the owner (0 = CLI-minted, no owner)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("--name is required")
	}
	canon, ok := canonicaliseScopes(*scopes)
	if !ok {
		return fmt.Errorf("--scopes must be one of: read, write, read,write (got %q)", *scopes)
	}

	ctx := context.Background()
	st, closeFn, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer closeFn()

	plaintext, err := generateAPIKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	row := store.APIKey{
		KeyHash:             hashAPIKey(plaintext),
		Name:                *name,
		Scopes:              canon,
		CreatedAt:           time.Now().UTC(),
		CreatedByTelegramID: *createdBy,
	}
	if err := st.APIKeys().Insert(ctx, row); err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	printNewKeyBanner(row.Name, row.Scopes, plaintext)
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list-keys", flag.ExitOnError)
	all := fs.Bool("all", false, "include revoked keys (default: active only)")
	_ = fs.Parse(args)

	ctx := context.Background()
	st, closeFn, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	rows, err := st.APIKeys().List(ctx)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	if !*all {
		filtered := rows[:0]
		for _, k := range rows {
			if k.IsActive() {
				filtered = append(filtered, k)
			}
		}
		rows = filtered
	}
	if len(rows) == 0 {
		fmt.Println("(no keys)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSCOPES\tOWNER\tCREATED\tSTATUS")
	for _, k := range rows {
		owner := "—"
		if k.CreatedByTelegramID != 0 {
			owner = strconv.FormatInt(k.CreatedByTelegramID, 10)
		}
		status := "active"
		if !k.IsActive() {
			status = "revoked " + k.RevokedAt.UTC().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			k.Name, k.Scopes, owner, k.CreatedAt.UTC().Format("2006-01-02 15:04"), status)
	}
	return tw.Flush()
}

func runRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke-key", flag.ExitOnError)
	name := fs.String("name", "", "name of the key to revoke (required)")
	_ = fs.Parse(args)
	if strings.TrimSpace(*name) == "" {
		return fmt.Errorf("--name is required")
	}

	ctx := context.Background()
	st, closeFn, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	if err := st.APIKeys().RevokeByName(ctx, *name, 0, time.Now().UTC()); err != nil {
		return fmt.Errorf("revoke %q: %w", *name, err)
	}
	fmt.Printf("revoked %q\n", *name)
	return nil
}

// ------------ helpers ------------

// openStore connects to the identity-service YDB using a fresh `yc` IAM token.
func openStore(ctx context.Context) (*ydbstore.Store, func(), error) {
	endpoint := os.Getenv("YDB_ENDPOINT")
	if endpoint == "" {
		return nil, nil, fmt.Errorf("YDB_ENDPOINT is required")
	}
	token, err := fetchIAMToken(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("yc iam create-token: %w (run `yc init` if you haven't)", err)
	}
	driver, err := ydb.Open(ctx, endpoint, ydb.WithAccessTokenCredentials(token))
	if err != nil {
		return nil, nil, fmt.Errorf("ydb.Open: %w", err)
	}
	st := ydbstore.NewFromDriver(driver)
	closer := func() {
		_ = st.Close()
	}
	return st, closer, nil
}

// fetchIAMToken shells out to `yc iam create-token` to get a short-lived IAM
// token usable as YDB Bearer credentials. Operator must have `yc` configured
// (yc init or a service-account key).
func fetchIAMToken(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "yc", "iam", "create-token", "--format=json").Output()
	if err != nil {
		// Fall back to the plain-text form, in case the user's yc version
		// doesn't support --format=json.
		out, err = exec.CommandContext(ctx, "yc", "iam", "create-token").Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}
	var parsed struct {
		IAMToken string `json:"iam_token"`
	}
	if jerr := json.Unmarshal(out, &parsed); jerr != nil || parsed.IAMToken == "" {
		// JSON envelope unexpected — treat the whole output as the token.
		return strings.TrimSpace(string(out)), nil
	}
	return parsed.IAMToken, nil
}

// canonicaliseScopes mirrors api.allowedScopes so the CLI and the HTTP path
// store identical strings. Returns the canonical form + ok.
func canonicaliseScopes(s string) (string, bool) {
	switch strings.TrimSpace(s) {
	case "read":
		return "read", true
	case "write", "read,write", "write,read":
		return "read,write", true
	}
	return "", false
}
