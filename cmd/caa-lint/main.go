// Command caa-lint evaluates CAA records for one or more domains.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tigertrust/caa-lint/internal/caa"
)

const usage = `caa-lint — TigerTrust CAA record check

Usage:
  caa-lint --domain example.com [flags]
  caa-lint --domains-file list.txt [flags]

Examples:
  # Check a single domain (parent-tree climb, human output)
  caa-lint --domain example.com

  # CI: require Let's Encrypt and Sectigo to be authorized
  caa-lint --domain example.com \
    --expect-issue letsencrypt.org \
    --expect-issue sectigo.com

  # Fail the build if the domain publishes no CAA at all
  caa-lint --domain example.com --fail-on-missing

  # Print example BIND / Route53 zone snippets
  caa-lint --domain example.com --suggest

  # JSON for pipelines
  caa-lint --domains-file list.txt --json

Exit codes:
  0  all domains pass policy
  1  CAA missing (with --fail-on-missing), or --expect-issue not satisfied
  2  usage / DNS error

Flags:
`

func main() {
	fs := flag.NewFlagSet("caa-lint", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	domain := fs.String("domain", "", "single domain to check")
	domainsFile := fs.String("domains-file", "", "file with one domain per line")
	var expect multi
	fs.Var(&expect, "expect-issue", "require this CA domain to be authorized (repeatable)")
	requireIODEF := fs.Bool("require-iodef", false, "fail if no iodef record")
	failOnMissing := fs.Bool("fail-on-missing", false, "fail if no CAA records are found at domain or any parent")
	suggest := fs.Bool("suggest", false, "print example BIND and Route53 CAA records")
	jsonOut := fs.Bool("json", false, "emit JSON")
	dnsOverride := fs.String("dns", "", "override DNS server, e.g. 1.1.1.1 or 1.1.1.1:53")
	timeout := fs.Duration("timeout", 5*time.Second, "overall DNS timeout per domain")
	iodefHint := fs.String("iodef", "mailto:security@example.com", "value to embed in --suggest output")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	var domains []string
	if *domain != "" {
		domains = append(domains, *domain)
	}
	if *domainsFile != "" {
		list, err := readDomainsFile(*domainsFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "domains-file:", err)
			os.Exit(2)
		}
		domains = append(domains, list...)
	}
	if len(domains) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	resolver := caa.NewMiekgResolver(*dnsOverride)
	opts := caa.Options{
		Resolver:     resolver,
		ExpectIssue:  expect,
		RequireIODEF: *requireIODEF,
		Timeout:      *timeout,
	}

	var worstExit int
	var reports []*caa.Report
	for _, d := range domains {
		r, err := caa.Evaluate(context.Background(), d, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", d, err)
			worstExit = max(worstExit, 2)
			continue
		}
		reports = append(reports, r)
		if r.MissingCAA && *failOnMissing {
			worstExit = max(worstExit, 1)
		}
		if len(r.Unauthorized) > 0 {
			worstExit = max(worstExit, 1)
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(reports)
	} else {
		for i, r := range reports {
			if i > 0 {
				fmt.Println()
			}
			printText(os.Stdout, r)
			if *suggest {
				fmt.Println()
				fmt.Println(caa.SuggestBIND(r.Domain, expect, *iodefHint))
				fmt.Println(caa.SuggestRoute53(r.Domain, expect, *iodefHint))
			}
		}
	}

	os.Exit(worstExit)
}

func printText(w *os.File, r *caa.Report) {
	fmt.Fprintf(w, "Domain:    %s\n", r.Domain)
	if r.MissingCAA {
		fmt.Fprintln(w, "CAA:       (missing — no records at domain or any parent)")
	} else {
		fmt.Fprintf(w, "FoundAt:   %s\n", r.FoundAt)
		for _, rec := range r.Records {
			fmt.Fprintf(w, "  %d %s %q\n", rec.Flag, rec.Tag, rec.Value)
		}
	}
	if r.DenyAll {
		fmt.Fprintln(w, "Policy:    DENY-ALL — `issue \";\"` forbids all issuance")
	}
	if r.WildcardGap {
		fmt.Fprintln(w, "Policy:    wildcard gap — `issue` present but no `issuewild`")
	}
	for _, line := range r.Policy {
		fmt.Fprintf(w, "Policy:    %s\n", line)
	}
	if len(r.Unauthorized) > 0 {
		fmt.Fprintf(w, "Unauthorized expected issuers: %s\n", strings.Join(r.Unauthorized, ", "))
	}
}

func readDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// multi captures a repeatable --expect-issue flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
