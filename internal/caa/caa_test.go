package caa

import (
	"context"
	"testing"
)

type fakeResolver struct {
	byName map[string][]Record
}

func (f *fakeResolver) LookupCAA(_ context.Context, name string) ([]Record, error) {
	return f.byName[name], nil
}

func TestEvaluate_FindsRecordsAtParent(t *testing.T) {
	r := &fakeResolver{byName: map[string][]Record{
		"example.com": {
			{Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			{Flag: 0, Tag: "iodef", Value: "mailto:sec@example.com"},
		},
	}}
	rep, err := Evaluate(context.Background(), "www.api.example.com", Options{Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	if rep.FoundAt != "example.com" {
		t.Fatalf("FoundAt = %q, want example.com", rep.FoundAt)
	}
	if rep.MissingCAA {
		t.Fatal("MissingCAA should be false")
	}
	if len(rep.Issue) != 1 || rep.Issue[0] != "letsencrypt.org" {
		t.Errorf("Issue = %v", rep.Issue)
	}
	if !rep.WildcardGap {
		t.Error("WildcardGap should be true")
	}
	if len(rep.IODEF) != 1 {
		t.Errorf("IODEF = %v", rep.IODEF)
	}
}

func TestEvaluate_MissingCAA(t *testing.T) {
	r := &fakeResolver{byName: map[string][]Record{}}
	rep, _ := Evaluate(context.Background(), "nope.example", Options{Resolver: r})
	if !rep.MissingCAA {
		t.Fatal("MissingCAA should be true")
	}
	if rep.FoundAt != "" {
		t.Errorf("FoundAt = %q, want empty", rep.FoundAt)
	}
}

func TestEvaluate_DenyAll(t *testing.T) {
	r := &fakeResolver{byName: map[string][]Record{
		"deny.example": {{Tag: "issue", Value: ";"}},
	}}
	rep, _ := Evaluate(context.Background(), "deny.example", Options{Resolver: r})
	if !rep.DenyAll {
		t.Fatal("DenyAll should be true for `issue \";\"`")
	}
}

func TestEvaluate_ExpectIssueUnauthorized(t *testing.T) {
	r := &fakeResolver{byName: map[string][]Record{
		"example.com": {{Tag: "issue", Value: "letsencrypt.org"}},
	}}
	rep, _ := Evaluate(context.Background(), "example.com", Options{
		Resolver:    r,
		ExpectIssue: []string{"sectigo.com"},
	})
	if len(rep.Unauthorized) != 1 || rep.Unauthorized[0] != "sectigo.com" {
		t.Fatalf("Unauthorized = %v, want [sectigo.com]", rep.Unauthorized)
	}
}

func TestEvaluate_ExpectIssueAuthorized(t *testing.T) {
	r := &fakeResolver{byName: map[string][]Record{
		"example.com": {
			{Tag: "issue", Value: "letsencrypt.org"},
			{Tag: "issue", Value: "sectigo.com; validationmethods=dns-01"},
		},
	}}
	rep, _ := Evaluate(context.Background(), "example.com", Options{
		Resolver:    r,
		ExpectIssue: []string{"sectigo.com"},
	})
	if len(rep.Unauthorized) != 0 {
		t.Fatalf("expected authorized, got %v", rep.Unauthorized)
	}
}

func TestEvaluate_WildcardGap(t *testing.T) {
	r := &fakeResolver{byName: map[string][]Record{
		"example.com": {
			{Tag: "issue", Value: "letsencrypt.org"},
			{Tag: "issuewild", Value: "letsencrypt.org"},
		},
	}}
	rep, _ := Evaluate(context.Background(), "example.com", Options{Resolver: r})
	if rep.WildcardGap {
		t.Fatal("WildcardGap should be false when issuewild present")
	}
}

func TestParent(t *testing.T) {
	cases := map[string]string{
		"a.b.c": "b.c",
		"b.c":   "c",
		"c":     "",
	}
	for in, want := range cases {
		if got := parent(in); got != want {
			t.Errorf("parent(%q)=%q want %q", in, got, want)
		}
	}
}

func TestSuggestBIND(t *testing.T) {
	out := SuggestBIND("example.com", []string{"letsencrypt.org"}, "mailto:sec@example.com")
	if len(out) == 0 || !contains(out, "issue \"letsencrypt.org\"") || !contains(out, "iodef") {
		t.Fatalf("suggestion malformed: %s", out)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
