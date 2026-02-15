#!/usr/bin/env bash
# Extract gitleaks test fixtures (tps/fps) by running the Go source.
#
# Requires: Go 1.24+, git, internet access
#
# Strategy: Clone gitleaks, patch Validate() to capture tps/fps in a global
# slice, build a Go program that calls every rule function, dump as JSON.
#
# Usage: ./scripts/extract-fixtures.sh [output-path]
# Default output: test/fixtures.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="${1:-$REPO_DIR/test/fixtures.json}"
TMPDIR="$(mktemp -d)"

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

echo "==> Cloning gitleaks..."
git clone --depth 1 https://github.com/gitleaks/gitleaks.git "$TMPDIR/gitleaks" 2>&1 | tail -1

echo "==> Patching Validate() to capture fixtures..."
# Add Fixture type and global slice
sed -i '/^func Validate(/i\
// Fixture stores tps\/fps for a rule (added for extraction)\
type Fixture struct {\
\tRuleID         string\
\tTruePositives  []string\
\tFalsePositives []string\
}\
\
// Fixtures is a global store populated by Validate calls\
var Fixtures []Fixture\
' "$TMPDIR/gitleaks/cmd/generate/config/utils/validate.go"

# Inject capture at start of Validate()
sed -i '/^func Validate(rule config.Rule, truePositives \[\]string, falsePositives \[\]string)/a\
\t// Capture fixtures before validation\
\tFixtures = append(Fixtures, Fixture{\
\t\tRuleID:         rule.RuleID,\
\t\tTruePositives:  truePositives,\
\t\tFalsePositives: falsePositives,\
\t})' "$TMPDIR/gitleaks/cmd/generate/config/utils/validate.go"

# Inject capture at start of ValidateWithPaths()
sed -i '/^func ValidateWithPaths(rule config.Rule, truePositives map\[string\]string, falsePositives map\[string\]string)/a\
\t// Capture path-based fixtures\
\ttpsList := make([]string, 0, len(truePositives))\
\tfor _, v := range truePositives {\
\t\ttpsList = append(tpsList, v)\
\t}\
\tfpsList := make([]string, 0, len(falsePositives))\
\tfor _, v := range falsePositives {\
\t\tfpsList = append(fpsList, v)\
\t}\
\tFixtures = append(Fixtures, Fixture{\
\t\tRuleID:         rule.RuleID,\
\t\tTruePositives:  tpsList,\
\t\tFalsePositives: fpsList,\
\t})' "$TMPDIR/gitleaks/cmd/generate/config/utils/validate.go"

echo "==> Creating extractor program..."
# Copy the main.go from the repo's rule list
cp "$SCRIPT_DIR/go-extractor/main.go" "$TMPDIR/gitleaks/cmd/extract-fixtures/main.go" 2>/dev/null || {
  # If main.go doesn't exist yet, generate from gitleaks' main.go
  mkdir -p "$TMPDIR/gitleaks/cmd/extract-fixtures"
  # Extract the rule function calls from gitleaks' main.go
  RULE_CALLS=$(sed -n '/configRules := \[/,/^[[:space:]]*}/p' "$TMPDIR/gitleaks/cmd/generate/config/main.go" | grep 'rules\.')
  
  cat > "$TMPDIR/gitleaks/cmd/extract-fixtures/main.go" << 'GOEOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func main() {
	configRules := []*config.Rule{
GOEOF
  echo "$RULE_CALLS" >> "$TMPDIR/gitleaks/cmd/extract-fixtures/main.go"
  cat >> "$TMPDIR/gitleaks/cmd/extract-fixtures/main.go" << 'GOEOF'
	}
	_ = configRules

	type JSONFixture struct {
		RuleID         string   `json:"ruleId"`
		TruePositives  []string `json:"tps"`
		FalsePositives []string `json:"fps"`
	}

	fixtures := make([]JSONFixture, len(utils.Fixtures))
	for i, f := range utils.Fixtures {
		fixtures[i] = JSONFixture{
			RuleID:         f.RuleID,
			TruePositives:  f.TruePositives,
			FalsePositives: f.FalsePositives,
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fixtures); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Extracted %d rule fixtures\n", len(fixtures))
}
GOEOF
}

# Patch go.mod version if needed (gitleaks may require unreleased Go)
GO_VERSION=$(go version | grep -oP '\d+\.\d+\.\d+')
sed -i "s/^go .*/go $GO_VERSION/" "$TMPDIR/gitleaks/go.mod"

echo "==> Building extractor..."
cd "$TMPDIR/gitleaks"
GOTOOLCHAIN=local go build -o "$TMPDIR/extract-fixtures" ./cmd/extract-fixtures 2>&1 | tail -5

echo "==> Extracting fixtures..."
"$TMPDIR/extract-fixtures" > "$OUTPUT" 2>&1

RULE_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT'))))")
TP_COUNT=$(python3 -c "import json; print(sum(len(r.get('tps') or []) for r in json.load(open('$OUTPUT'))))")
FP_COUNT=$(python3 -c "import json; print(sum(len(r.get('fps') or []) for r in json.load(open('$OUTPUT'))))")

echo "==> Done! $RULE_COUNT rules, $TP_COUNT true positives, $FP_COUNT false positives"
echo "    Output: $OUTPUT"
