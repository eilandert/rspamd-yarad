package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/eilandert/rspamd-yarad/internal/yarad"
)

// defaultRulesURL is the rolling release directory that generate-rules.sh
// publishes compiled.yac + its manifest to. Override with -url / YARAD_RULES_URL
// (e.g. to point at a mirror).
const defaultRulesURL = "https://github.com/eilandert/rspamd-yarad/releases/download/rules-current"

// cmdFetchRules downloads an updated compiled rule bundle into the cache, driven
// by the published manifest: it fetches the manifest first and updates only when
// the remote version is newer and the libyara version matches. It verifies the
// download (sha256) and swaps atomically, keeping one backup. It is the
// counterpart to generate-rules.sh and the primary rule-update path for both
// Docker and non-Docker users (no local yarac / compile).
//
// Exit codes: 0 = up to date or updated successfully; 2 = error (kept the current
// bundle). A `serve`-time interval fetch reuses internal/yarad.FetchRules.
func cmdFetchRules(args []string) int {
	cfg := yarad.LoadConfig()

	fs := flag.NewFlagSet("fetch-rules", flag.ContinueOnError)
	url := fs.String("url", envOr("YARAD_RULES_URL", defaultRulesURL), "base URL holding compiled.yac + its manifest (YARAD_RULES_URL)")
	cacheDir := fs.String("cache-dir", firstNonEmpty(cfg.CacheDir, "/var/cache/yarad"), "cache dir for the live bundle (YARAD_CACHE_DIR)")
	timeout := fs.Duration("timeout", 60*time.Second, "overall HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	hc := &http.Client{Timeout: *timeout}

	res, err := yarad.FetchRules(ctx, *url, *cacheDir, libyaraVersion, hc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yarad fetch-rules:", err)
		return 2
	}
	if res.Updated {
		fmt.Printf("fetch-rules: %s — restart or SIGHUP yarad to load the new bundle\n", res.Reason)
	} else {
		fmt.Printf("fetch-rules: %s\n", res.Reason)
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
