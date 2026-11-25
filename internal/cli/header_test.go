package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluateValidFor(t *testing.T) {
	alerts, policy := goodArgs(t)
	eval := []string{"evaluate", "--alerts", alerts, "--policy", policy, "--now", "2026-01-15T12:00:00Z", "--json"}
	for flag, want := range map[string]string{"": `"valid_for": 60,`, "1": `"valid_for": 1,`, "3600": `"valid_for": 3600,`} {
		args := eval
		if flag != "" {
			args = append(append([]string{}, eval...), "--valid-for", flag)
		}
		_, out, errs := run(t, args...)
		if !strings.Contains(out, want) || !strings.Contains(out, `"observed": true,`) || !strings.Contains(out, `"declaration": null,`) {
			t.Errorf("--valid-for %q: stdout %q stderr %q", flag, out, errs)
		}
	}
	for _, bad := range []string{"0", "-1", "60s", "1.5", ""} {
		code, out, errs := run(t, append(append([]string{}, eval...), "--valid-for="+bad)...)
		if code != ExitConfig || out != "" || !strings.Contains(errs, "valid-for") {
			t.Errorf("--valid-for=%q: exit %d stdout %q stderr %q", bad, code, out, errs)
		}
	}
}

func TestDeclarationValidateAndEmit(t *testing.T) {
	alerts, policy := goodArgs(t)
	base := string(readFile(t, policy))
	digest := "sha256:" + strings.Repeat("c", 64)
	write := func(line string) string {
		p := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(p, []byte(base+"\n"+line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	declared := write("declaration: " + digest)
	if code, _, errs := run(t, "validate", "--policy", declared); code != 0 {
		t.Fatalf("validate: exit %d %q", code, errs)
	}
	if _, out, errs := run(t, "evaluate", "--alerts", alerts, "--policy", declared, "--json"); !strings.Contains(out, `"declaration": "`+digest+`",`) {
		t.Fatalf("stdout %q stderr %q", out, errs)
	}
	code, _, errs := run(t, "validate", "--policy", write("declaration: sha256:short"))
	if code != ExitPolicy || !strings.Contains(errs, "declaration") {
		t.Fatalf("bad declaration: exit %d %q", code, errs)
	}
}
