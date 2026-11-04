// Package caa evaluates CAA records for a domain and reports policy findings.
package caa

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Record is a single CAA record.
type Record struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// Report is the result of a CAA evaluation for one domain.
type Report struct {
	Domain       string   `json:"domain"`
	FoundAt      string   `json:"foundAt,omitempty"` // which label returned the records; empty if none
	Records      []Record `json:"records"`
	Issue        []string `json:"issue"`
	IssueWild    []string `json:"issueWild"`
	IODEF        []string `json:"iodef"`
	IssueMail    []string `json:"issueMail,omitempty"`
	DenyAll      bool     `json:"denyAll"`      // `issue ";"`
	MissingCAA   bool     `json:"missingCAA"`   // no records at any parent
	WildcardGap  bool     `json:"wildcardGap"`  // `issue` present but no `issuewild`
	Unauthorized []string `json:"unauthorized"` // CAs from --expect-issue that aren't permitted
	Policy       []string `json:"policy"`       // high-level advice / warnings
}

// Resolver is the DNS entry point so tests can inject behaviour.
type Resolver interface {
	LookupCAA(ctx context.Context, name string) ([]Record, error)
}

// Options controls Evaluate.
type Options struct {
	Resolver      Resolver
	ExpectIssue   []string
	RequireIODEF  bool
	Timeout       time.Duration
	// IsPublicSuffix returns true when name is at/above the registry boundary.
	// For v1 we do not pull a full PSL; we stop at label count == 1.
	IsPublicSuffix func(name string) bool
}

// Evaluate climbs the label tree per RFC 8659 §3 and classifies the records.
func Evaluate(ctx context.Context, domain string, opts Options) (*Report, error) {
	if opts.Resolver == nil {
		return nil, fmt.Errorf("caa: nil resolver")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	name := strings.TrimSuffix(strings.ToLower(domain), ".")
	r := &Report{Domain: name}

	for current := name; current != ""; current = parent(current) {
		recs, err := opts.Resolver.LookupCAA(ctx, current)
		if err != nil {
			return nil, err
		}
		if len(recs) > 0 {
			r.FoundAt = current
			r.Records = recs
			break
		}
		if opts.IsPublicSuffix != nil && opts.IsPublicSuffix(current) {
			break
		}
	}

	r.MissingCAA = len(r.Records) == 0
	for _, rec := range r.Records {
		switch rec.Tag {
		case "issue":
			r.Issue = append(r.Issue, rec.Value)
			if strings.TrimSpace(rec.Value) == ";" {
				r.DenyAll = true
			}
		case "issuewild":
			r.IssueWild = append(r.IssueWild, rec.Value)
		case "iodef":
			r.IODEF = append(r.IODEF, rec.Value)
		case "issuemail":
			r.IssueMail = append(r.IssueMail, rec.Value)
		}
	}

	if len(r.Issue) > 0 && len(r.IssueWild) == 0 && !r.DenyAll {
		r.WildcardGap = true
		r.Policy = append(r.Policy, "issue present but no issuewild — wildcards may fall back to the `issue` set (double-check if you intend to forbid wildcards)")
	}
	if opts.RequireIODEF && len(r.IODEF) == 0 {
		r.Policy = append(r.Policy, "--require-iodef: no iodef record at "+coalesce(r.FoundAt, r.Domain))
	}
	for _, want := range opts.ExpectIssue {
		if !issueAuthorizes(r.Issue, r.IssueWild, want) {
			r.Unauthorized = append(r.Unauthorized, want)
		}
	}
	return r, nil
}

func issueAuthorizes(issue, issueWild []string, ca string) bool {
	ca = strings.TrimSpace(strings.ToLower(ca))
	for _, v := range append(issue, issueWild...) {
		// Value is `issuer-domain [; parameters]`. We only match the issuer-domain.
		part := strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
		part = strings.ToLower(part)
		if part == ca {
			return true
		}
	}
	return false
}

func parent(name string) string {
	idx := strings.Index(name, ".")
	if idx < 0 {
		return ""
	}
	return name[idx+1:]
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// MiekgResolver is a Resolver backed by miekg/dns using the system resolvers or an override.
type MiekgResolver struct {
	Servers []string // e.g. ["1.1.1.1:53"]; empty means /etc/resolv.conf fallback
	Client  *dns.Client
}

// NewMiekgResolver returns a resolver with sensible defaults.
func NewMiekgResolver(override string) *MiekgResolver {
	m := &MiekgResolver{Client: &dns.Client{Timeout: 3 * time.Second}}
	if override != "" {
		host := override
		if !strings.Contains(host, ":") {
			host += ":53"
		}
		m.Servers = []string{host}
	} else {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err == nil {
			for _, s := range cfg.Servers {
				m.Servers = append(m.Servers, net.JoinHostPort(s, cfg.Port))
			}
		}
	}
	if len(m.Servers) == 0 {
		m.Servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	return m
}

// LookupCAA implements Resolver.
func (m *MiekgResolver) LookupCAA(ctx context.Context, name string) ([]Record, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeCAA)
	msg.RecursionDesired = true
	var lastErr error
	for _, srv := range m.Servers {
		resp, _, err := m.Client.ExchangeContext(ctx, msg, srv)
		if err != nil {
			lastErr = err
			continue
		}
		out := make([]Record, 0, len(resp.Answer))
		for _, a := range resp.Answer {
			if c, ok := a.(*dns.CAA); ok {
				out = append(out, Record{Flag: c.Flag, Tag: c.Tag, Value: c.Value})
			}
		}
		return out, nil
	}
	return nil, lastErr
}

// SuggestBIND prints example BIND zone-file lines authorizing the given CAs.
func SuggestBIND(domain string, cas []string, iodef string) string {
	if len(cas) == 0 {
		cas = []string{"letsencrypt.org"}
	}
	var b strings.Builder
	b.WriteString("; BIND / RFC 1035 CAA suggestion for " + domain + "\n")
	for _, ca := range cas {
		fmt.Fprintf(&b, "%s.\tCAA 0 issue \"%s\"\n", domain, ca)
	}
	for _, ca := range cas {
		fmt.Fprintf(&b, "%s.\tCAA 0 issuewild \"%s\"\n", domain, ca)
	}
	if iodef != "" {
		fmt.Fprintf(&b, "%s.\tCAA 0 iodef \"%s\"\n", domain, iodef)
	}
	return b.String()
}

// SuggestRoute53 prints an aws-cli change-batch snippet.
func SuggestRoute53(domain string, cas []string, iodef string) string {
	if len(cas) == 0 {
		cas = []string{"letsencrypt.org"}
	}
	var lines []string
	for _, ca := range cas {
		lines = append(lines, fmt.Sprintf(`        "0 issue \"%s\""`, ca))
		lines = append(lines, fmt.Sprintf(`        "0 issuewild \"%s\""`, ca))
	}
	if iodef != "" {
		lines = append(lines, fmt.Sprintf(`        "0 iodef \"%s\""`, iodef))
	}
	tmpl := `# Route53 change-batch for %s
{
  "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "%s.",
      "Type": "CAA",
      "TTL": 300,
      "ResourceRecords": [
%s
      ]
    }
  }]
}
`
	body := strings.Join(mapRR(lines), ",\n")
	return fmt.Sprintf(tmpl, domain, domain, body)
}

func mapRR(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		out = append(out, fmt.Sprintf(`        { "Value": %s }`, strings.TrimSpace(l)))
	}
	return out
}
