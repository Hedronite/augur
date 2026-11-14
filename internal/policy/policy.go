// Package policy parses and validates an augur.policy/v0 document.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Hedronite/augur/internal/model"
)

// Document constants and defaults (SPEC §4).
const (
	schemaID             = "augur.policy/v0"
	defaultHostLabel     = "host"
	defaultReplicaLabel  = "replica"
	defaultRedHold       = 10 * time.Minute
	defaultDeadmanWindow = 5 * time.Minute
	redHoldKeyword       = "node_exporter_red_hold"
	// maxValueBytes bounds every excerpt stored in a FieldError. render.Errors
	// truncates again; this only keeps the parser from holding a long string.
	maxValueBytes = 200
	// deferredAfter marks an escalate.after that names node_exporter_red_hold.
	// Resolution waits until the whole document is read, because the key may
	// appear after the rules.
	deferredAfter = time.Duration(-1)
)

var (
	// durationPattern is the grammar the policy schema accepts, on purpose
	// narrower than time.ParseDuration: a whole number and one unit.
	durationPattern = regexp.MustCompile(`^[0-9]+(s|m|h)$`)
	// dateTimePattern mirrors decode's timestamp pattern, so that expires_at is
	// accepted exactly when the schema's date-time format accepts it.
	dateTimePattern = regexp.MustCompile(
		`^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`)
	yamlLinePattern = regexp.MustCompile(`line ([0-9]+)`)
)

// Parse reads strict YAML (unknown keys are errors) and returns the policy
// with defaults applied and SHA256 set. It collects every problem rather than
// stopping at the first; a non-empty slice means exit 4. The returned policy
// is the zero value whenever the slice is non-empty, so a half-read policy can
// never be used.
func Parse(data []byte) (model.Policy, []model.FieldError) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return model.Policy{}, []model.FieldError{{
			Line:    yamlErrorLine(err),
			Problem: "the policy is not valid YAML",
			Value:   excerpt(err.Error()),
			Fix:     "check the indentation and quoting near this line",
		}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return model.Policy{}, []model.FieldError{{
			Problem: "the policy is empty",
			Fix:     "start with schema: " + schemaID,
		}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return model.Policy{}, []model.FieldError{{
			Line:    root.Line,
			Problem: "the policy must be a mapping of keys to values",
			Value:   excerpt(root.Value),
			Fix:     "write each setting as key: value on its own line",
		}}
	}

	p := model.Policy{
		HostLabel:           defaultHostLabel,
		ReplicaLabel:        defaultReplicaLabel,
		NodeExporterRedHold: defaultRedHold,
		Watchdog:            model.Watchdog{DeadmanWindow: defaultDeadmanWindow},
		SHA256:              sha256Hex(data),
	}
	v := &validator{p: &p}
	v.document(root)
	if len(v.errs) > 0 {
		return model.Policy{}, v.errs
	}
	return p, nil
}

// validator walks the document once, collecting every problem it finds.
type validator struct {
	p    *model.Policy
	errs []model.FieldError
}

// add records one problem at a field path.
func (v *validator) add(n *yaml.Node, path, problem, fix string) {
	line := 0
	if n != nil {
		line = n.Line
	}
	v.errs = append(v.errs, model.FieldError{
		Line:    line,
		Path:    path,
		Value:   scalarText(n),
		Problem: problem,
		Fix:     fix,
	})
}

// document validates the top-level mapping.
func (v *validator) document(root *yaml.Node) {
	seen := make(map[string]bool)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], root.Content[i+1]
		name := key.Value
		if seen[name] {
			v.add(key, name, "duplicate key", "keep a single "+name+" entry")
			continue
		}
		seen[name] = true
		switch name {
		case "schema":
			v.schemaVersion(val, name)
		case "default":
			if sev, ok := v.severity(val, name); ok {
				v.p.Default = sev
			}
		case "host_label":
			if s, ok := v.nonEmptyString(val, name); ok {
				v.p.HostLabel = s
			}
		case "replica_label":
			if s, ok := v.nonEmptyString(val, name); ok {
				v.p.ReplicaLabel = s
			}
		case "replicas":
			if list, ok := v.slugList(val, name, true); ok {
				v.p.Replicas = list
			}
		case "watchdog":
			v.watchdog(val, name)
		case "node_exporter_red_hold":
			if d, ok := v.duration(val, name); ok {
				v.p.NodeExporterRedHold = d
			}
		case "first_class_hosts":
			if list, ok := v.slugList(val, name, false); ok {
				v.p.FirstClassHosts = list
			}
		case "rules":
			v.rules(val, name)
		case "holds":
			v.holds(val, name)
		default:
			v.add(key, name, "unknown key", "remove it, or check the spelling against the policy schema")
		}
	}
	for _, required := range []string{"schema", "default", "watchdog", "rules"} {
		if !seen[required] {
			v.add(root, required, "required", "add a "+required+" entry")
		}
	}
	// NodeExporterRedHold is known only now, so keyword escalations resolve here.
	for i := range v.p.Rules {
		if e := v.p.Rules[i].Escalate; e != nil && e.After == deferredAfter {
			e.After = v.p.NodeExporterRedHold
		}
	}
}

// schemaVersion checks the document identity.
func (v *validator) schemaVersion(n *yaml.Node, path string) {
	if n.Kind != yaml.ScalarNode {
		v.add(n, path, "must be a string", "write schema: "+schemaID)
		return
	}
	if n.Value != schemaID {
		v.add(n, path, "unsupported policy schema", "use "+schemaID)
	}
}

// scalarIsString reports whether a scalar reaches JSON as a string, which is
// what the policy schema accepts wherever it says type: string. A null, an int,
// a float and a bool reach JSON as null, number or boolean and are refused; a
// timestamp and a binary value reach JSON as strings and are accepted.
func scalarIsString(n *yaml.Node) bool {
	switch n.Tag {
	case "!!str", "!!timestamp", "!!binary",
		"tag:yaml.org,2002:str", "tag:yaml.org,2002:timestamp", "tag:yaml.org,2002:binary":
		return true
	}
	return false
}

// nonEmptyString accepts a scalar with at least one character.
func (v *validator) nonEmptyString(n *yaml.Node, path string) (string, bool) {
	if n.Kind != yaml.ScalarNode || !scalarIsString(n) {
		v.add(n, path, "must be a string", "quote the value, or write it as a bare word")
		return "", false
	}
	if n.Value == "" {
		v.add(n, path, "must not be empty", "name the label this key reads")
		return "", false
	}
	return n.Value, true
}

// severity accepts YELLOW or RED. GREEN is refused everywhere: a policy can
// only raise severity, and the fail-closed default is YELLOW.
func (v *validator) severity(n *yaml.Node, path string) (model.Severity, bool) {
	if n.Kind != yaml.ScalarNode {
		v.add(n, path, "must be YELLOW or RED", "write the severity as a bare word")
		return "", false
	}
	switch n.Value {
	case "YELLOW":
		return model.Yellow, true
	case "RED":
		return model.Red, true
	case "GREEN":
		v.add(n, path, "GREEN is not allowed here", "a policy can only raise severity; use YELLOW or RED")
		return "", false
	default:
		v.add(n, path, "unknown severity", "use YELLOW or RED")
		return "", false
	}
}

// duration accepts the schema's duration grammar.
func (v *validator) duration(n *yaml.Node, path string) (time.Duration, bool) {
	if n.Kind != yaml.ScalarNode {
		v.add(n, path, "must be a duration", "write a whole number and a unit, for example 90s, 10m or 2h")
		return 0, false
	}
	if !durationPattern.MatchString(n.Value) {
		v.add(n, path, "is not a duration", "write a whole number and a unit, for example 90s, 10m or 2h")
		return 0, false
	}
	unit := n.Value[len(n.Value)-1]
	amount, err := strconv.ParseInt(n.Value[:len(n.Value)-1], 10, 64)
	if err != nil {
		v.add(n, path, "is too large", "use a smaller duration")
		return 0, false
	}
	var scale time.Duration
	switch unit {
	case 's':
		scale = time.Second
	case 'm':
		scale = time.Minute
	case 'h':
		scale = time.Hour
	}
	if amount > math.MaxInt64/int64(scale) {
		v.add(n, path, "is too large", "use a smaller duration")
		return 0, false
	}
	return time.Duration(amount) * scale, true
}

// slugList validates a list of replica or host slugs.
func (v *validator) slugList(n *yaml.Node, path string, requiredSome bool) ([]string, bool) {
	if n.Kind != yaml.SequenceNode {
		v.add(n, path, "must be a list", "write it as [slug, slug] or as a block list")
		return nil, false
	}
	if requiredSome && len(n.Content) == 0 {
		v.add(n, path, "must list at least one replica",
			"omit the key for single-view mode, or list the replica slugs that reach this source")
		return nil, false
	}
	out := make([]string, 0, len(n.Content))
	seen := make(map[string]bool, len(n.Content))
	okAll := true
	for i, item := range n.Content {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		if item.Kind != yaml.ScalarNode || !scalarIsString(item) {
			v.add(item, itemPath, "must be a slug", "write it as a bare word, not a number or an empty value")
			okAll = false
			continue
		}
		if !model.SlugPattern.MatchString(item.Value) {
			v.add(item, itemPath, "is not a slug",
				"use 1-32 lowercase letters, digits or hyphens")
			okAll = false
			continue
		}
		if seen[item.Value] {
			v.add(item, itemPath, "duplicate entry", "list each value once")
			okAll = false
			continue
		}
		seen[item.Value] = true
		out = append(out, item.Value)
	}
	return out, okAll
}

// catalogue walks the keys of a nested mapping and reports unknown ones.
func (v *validator) catalogue(n *yaml.Node, path string, allowed map[string]bool) map[string]*yaml.Node {
	out := make(map[string]*yaml.Node, len(allowed))
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		keyPath := path + "." + key.Value
		if !allowed[key.Value] {
			v.add(key, keyPath, "unknown key", "remove it, or check the spelling against the policy schema")
			continue
		}
		if _, dup := out[key.Value]; dup {
			v.add(key, keyPath, "duplicate key", "keep a single "+key.Value+" entry")
			continue
		}
		out[key.Value] = val
	}
	return out
}

// watchdog validates the heartbeat block.
func (v *validator) watchdog(n *yaml.Node, path string) {
	if n.Kind != yaml.MappingNode {
		v.add(n, path, "must be a mapping", "set alertname (and optionally deadman_window)")
		return
	}
	keys := v.catalogue(n, path, map[string]bool{"alertname": true, "deadman_window": true})
	alertName, ok := keys["alertname"]
	if !ok {
		v.add(n, path+".alertname", "required", "name the heartbeat alert, usually Watchdog")
	} else if s, ok := v.nonEmptyString(alertName, path+".alertname"); ok {
		v.p.Watchdog.AlertName = s
	}
	if window, ok := keys["deadman_window"]; ok {
		if d, ok := v.duration(window, path+".deadman_window"); ok {
			v.p.Watchdog.DeadmanWindow = d
		}
	}
}

// rules validates the rule list.
func (v *validator) rules(n *yaml.Node, path string) {
	if n.Kind != yaml.SequenceNode {
		v.add(n, path, "must be a list", "write it as a block list, or [] for a default-only policy")
		return
	}
	ids := make(map[string]bool, len(n.Content))
	rules := make([]model.Rule, 0, len(n.Content))
	for i, item := range n.Content {
		rule, ok := v.rule(item, fmt.Sprintf("%s[%d]", path, i), ids)
		if ok {
			rules = append(rules, rule)
		}
	}
	v.p.Rules = rules
}

// rule validates one rule.
func (v *validator) rule(n *yaml.Node, path string, ids map[string]bool) (model.Rule, bool) {
	if n.Kind != yaml.MappingNode {
		v.add(n, path, "must be a mapping", "set id, match and severity")
		return model.Rule{}, false
	}
	keys := v.catalogue(n, path, map[string]bool{
		"id": true, "match": true, "severity": true, "escalate": true,
	})
	var rule model.Rule
	okAll := true

	if idNode, ok := keys["id"]; !ok {
		v.add(n, path+".id", "required", "give the rule a lowercase id")
		okAll = false
	} else if id, ok := v.identifier(idNode, path+".id"); ok {
		if ids[id] {
			v.add(idNode, path+".id", "duplicate rule id", "give each rule its own id")
			okAll = false
		} else {
			ids[id] = true
			rule.ID = id
		}
	} else {
		okAll = false
	}

	if matchNode, ok := keys["match"]; !ok {
		v.add(n, path+".match", "required", "add the labels this rule matches")
		okAll = false
	} else if match, ok := v.match(matchNode, path+".match"); ok {
		rule.Match = match
	} else {
		okAll = false
	}

	if sevNode, ok := keys["severity"]; !ok {
		v.add(n, path+".severity", "required", "add severity: YELLOW or RED")
		okAll = false
	} else if sev, ok := v.severity(sevNode, path+".severity"); ok {
		rule.Severity = sev
	} else {
		okAll = false
	}

	if escNode, ok := keys["escalate"]; ok {
		if esc, ok := v.escalate(escNode, path+".escalate"); ok {
			rule.Escalate = esc
		} else {
			okAll = false
		}
	}
	return rule, okAll
}

// escalate validates an escalation block.
func (v *validator) escalate(n *yaml.Node, path string) (*model.Escalate, bool) {
	if n.Kind != yaml.MappingNode {
		v.add(n, path, "must be a mapping", "set to, after and hosts")
		return nil, false
	}
	keys := v.catalogue(n, path, map[string]bool{"to": true, "after": true, "hosts": true})
	esc := &model.Escalate{After: deferredAfter}
	okAll := true

	to, ok := keys["to"]
	switch {
	case !ok:
		v.add(n, path+".to", "required", "add to: RED")
		okAll = false
	case to.Kind != yaml.ScalarNode || to.Value != "RED":
		v.add(to, path+".to", "an escalation can only go to RED", "use to: RED")
		okAll = false
	}

	if after, ok := keys["after"]; !ok {
		v.add(n, path+".after", "required", "add the age at which the alert escalates")
		okAll = false
	} else if after.Kind == yaml.ScalarNode && after.Value == redHoldKeyword {
		// Naming the key defers resolution until the whole document is read,
		// because node_exporter_red_hold may appear after the rules.
		esc.After = deferredAfter
	} else if d, ok := v.duration(after, path+".after"); ok {
		esc.After = d
	} else {
		okAll = false
	}

	if hosts, ok := keys["hosts"]; !ok {
		v.add(n, path+".hosts", "required", "use first_class or all")
		okAll = false
	} else if hosts.Kind != yaml.ScalarNode ||
		(hosts.Value != string(model.HostsFirstClass) && hosts.Value != string(model.HostsAll)) {
		v.add(hosts, path+".hosts", "unknown escalation scope", "use first_class or all")
		okAll = false
	} else {
		esc.Hosts = model.EscalateHosts(hosts.Value)
	}
	return esc, okAll
}

// match validates a label matcher set: every entry must match, and an empty
// set matches nothing, so it is refused.
func (v *validator) match(n *yaml.Node, path string) (model.Match, bool) {
	if n.Kind != yaml.MappingNode {
		v.add(n, path, "must be a mapping of labels to values", "write it as {alertname: SomeAlert}")
		return nil, false
	}
	if len(n.Content) == 0 {
		v.add(n, path, "must match at least one label", "add a label, for example alertname")
		return nil, false
	}
	out := make(model.Match, len(n.Content)/2)
	okAll := true
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		if key.Value == "" {
			v.add(key, path, "a matcher needs a label name", "name the label to read")
			okAll = false
			continue
		}
		entryPath := path + "." + key.Value
		matcher, ok := v.matcher(val, entryPath)
		if !ok {
			okAll = false
			continue
		}
		out[key.Value] = matcher
	}
	return out, okAll
}

// matcher accepts label equality or an anchored regular expression.
func (v *validator) matcher(n *yaml.Node, path string) (model.Matcher, bool) {
	if n.Kind == yaml.ScalarNode {
		if !scalarIsString(n) {
			// A null after the key means the matcher has no value; the schema
			// accepts a string or {regex: ...}, and a null is neither.
			v.add(n, path, "must be a string",
				"give the label a value, or write {regex: pattern} to match by pattern")
			return model.Matcher{}, false
		}
		return model.Matcher{Equals: n.Value}, true
	}
	if n.Kind != yaml.MappingNode {
		v.add(n, path, "must be a value or a {regex: ...} mapping", "write the value as a bare word")
		return model.Matcher{}, false
	}
	keys := v.catalogue(n, path, map[string]bool{"regex": true})
	expr, ok := keys["regex"]
	if !ok {
		v.add(n, path+".regex", "required", "write {regex: \u0022pattern\u0022}")
		return model.Matcher{}, false
	}
	if expr.Kind != yaml.ScalarNode || !scalarIsString(expr) || expr.Value == "" {
		v.add(expr, path+".regex", "must be a pattern", "write a non-empty RE2 pattern")
		return model.Matcher{}, false
	}
	return v.compile(expr, path+".regex")
}

// compile anchors and compiles a policy pattern. JSON Schema cannot see this,
// so it is the engine's own check: it is what fixture 79 exercises.
func (v *validator) compile(n *yaml.Node, path string) (model.Matcher, bool) {
	re, err := regexp.Compile("^(?:" + n.Value + ")$")
	if err != nil {
		v.add(n, path, "is not a valid regular expression", "fix the pattern; RE2 syntax: "+excerpt(err.Error()))
		return model.Matcher{}, false
	}
	return model.Matcher{Regex: re}, true
}

// holds validates the hold list.
func (v *validator) holds(n *yaml.Node, path string) {
	if n.Kind != yaml.SequenceNode {
		v.add(n, path, "must be a list", "write it as a block list")
		return
	}
	ids := make(map[string]bool, len(n.Content))
	holds := make([]model.Hold, 0, len(n.Content))
	for i, item := range n.Content {
		hold, ok := v.hold(item, fmt.Sprintf("%s[%d]", path, i), ids)
		if ok {
			holds = append(holds, hold)
		}
	}
	v.p.Holds = holds
}

// hold validates one hold.
func (v *validator) hold(n *yaml.Node, path string, ids map[string]bool) (model.Hold, bool) {
	if n.Kind != yaml.MappingNode {
		v.add(n, path, "must be a mapping", "set id, match and kind")
		return model.Hold{}, false
	}
	keys := v.catalogue(n, path, map[string]bool{
		"id": true, "match": true, "kind": true, "expires_at": true,
	})
	var hold model.Hold
	okAll := true

	if idNode, ok := keys["id"]; !ok {
		v.add(n, path+".id", "required", "give the hold a lowercase id")
		okAll = false
	} else if id, ok := v.identifier(idNode, path+".id"); ok {
		if ids[id] {
			v.add(idNode, path+".id", "duplicate hold id", "give each hold its own id")
			okAll = false
		} else {
			ids[id] = true
			hold.ID = id
		}
	} else {
		okAll = false
	}

	if matchNode, ok := keys["match"]; !ok {
		v.add(n, path+".match", "required", "add the labels this hold covers")
		okAll = false
	} else if match, ok := v.match(matchNode, path+".match"); ok {
		hold.Match = match
	} else {
		okAll = false
	}

	kindNode, hasKind := keys["kind"]
	expiresNode, hasExpires := keys["expires_at"]
	switch {
	case !hasKind:
		v.add(n, path+".kind", "required", "use expected_dark, known_hold or announced_dark")
		okAll = false
	case kindNode.Kind != yaml.ScalarNode ||
		(kindNode.Value != string(model.HoldExpectedDark) &&
			kindNode.Value != string(model.HoldKnown) &&
			kindNode.Value != string(model.HoldAnnouncedDark)):
		v.add(kindNode, path+".kind", "unknown hold kind",
			"use expected_dark, known_hold or announced_dark")
		okAll = false
	default:
		hold.Kind = model.HoldKind(kindNode.Value)
	}

	switch {
	case hold.Kind == model.HoldAnnouncedDark && !hasExpires:
		v.add(n, path+".expires_at", "required for an announced dark",
			"add expires_at so the dark clears itself")
		okAll = false
	case hold.Kind != model.HoldAnnouncedDark && hasExpires:
		v.add(expiresNode, path+".expires_at", "only announced_dark takes expires_at",
			"remove expires_at, or make this hold an announced_dark")
		okAll = false
	case hasExpires:
		ts, ok := parseDateTime(expiresNode.Value)
		if expiresNode.Kind != yaml.ScalarNode || !ok {
			v.add(expiresNode, path+".expires_at", "not an RFC3339 time",
				"write the expiry as 2026-01-15T12:00:00Z")
			okAll = false
		} else {
			hold.ExpiresAt = ts
		}
	}
	return hold, okAll
}

// identifier accepts a bounded rule or hold id.
func (v *validator) identifier(n *yaml.Node, path string) (string, bool) {
	if n.Kind != yaml.ScalarNode || !scalarIsString(n) {
		v.add(n, path, "must be a string", "write a lowercase id")
		return "", false
	}
	if !model.IDPattern.MatchString(n.Value) {
		v.add(n, path, "is not a valid id",
			"use 1-64 lowercase letters, digits or hyphens, starting with a letter or digit")
		return "", false
	}
	return n.Value, true
}

// parseDateTime accepts what the schema's date-time format accepts.
func parseDateTime(s string) (time.Time, bool) {
	if !dateTimePattern.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.ToUpper(s))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// scalarText is the raw text of a scalar node, bounded.
func scalarText(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return excerpt(n.Value)
}

// excerpt bounds a stored value to maxValueBytes without splitting a rune. The
// bound is on bytes, not runes: a rune count can admit a string several times
// the size, and an input that is not valid UTF-8 converts to more bytes than it
// started with.
func excerpt(s string) string {
	if len(s) <= maxValueBytes {
		return s
	}
	cut := 0
	for i := range s {
		if i > maxValueBytes {
			break
		}
		cut = i
	}
	return s[:cut]
}

// yamlErrorLine pulls the line number out of a yaml.v3 error.
func yamlErrorLine(err error) int {
	if m := yamlLinePattern.FindStringSubmatch(err.Error()); m != nil {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			return n
		}
	}
	return 0
}

// sha256Hex is the lowercase hex digest of the exact policy bytes.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
