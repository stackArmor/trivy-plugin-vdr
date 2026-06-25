#!/usr/bin/env bash
#
# local-test.sh — build vdr from source and run it against the current
# Kubernetes context, writing JSON + HTML reports.
#
# This runs the freshly built binary directly (no plugin install), so it picks
# up local changes on every run. vdr shells out to `trivy image`, so Trivy must
# be installed and on PATH. Registry auth optionally uses `gcloud` and `aws`.
#
# Usage:
#   scripts/local-test.sh [extra vdr flags...]
#
# Examples:
#   scripts/local-test.sh                              # all namespaces, default output
#   scripts/local-test.sh --namespace default          # single namespace
#   scripts/local-test.sh --debug                       # verbose progress logs
#   scripts/local-test.sh --skip-registry-auth          # disable auto auth
#   OUT_DIR=/tmp/vdr scripts/local-test.sh              # custom output directory
#
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_dir="${OUT_DIR:-$repo_root}"
json_out="$out_dir/output.json"
html_out="$out_dir/output.html"

if ! command -v trivy >/dev/null 2>&1; then
  echo "error: trivy is not installed or not on PATH (vdr scans images via 'trivy image')." >&2
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "warning: kubectl not found; vdr uses your current kubeconfig context directly." >&2
else
  echo "kube context: $(kubectl config current-context 2>/dev/null || echo '<none>')"
fi

mkdir -p "$out_dir"

echo "building vdr..."
go build -o "$repo_root/vdr" ./cmd/vdr

# Default to scanning all namespaces unless the caller passes a namespace
# selector. Reports are written to $out_dir.
args=("k8s" "--output" "$json_out" "--html-output" "$html_out")
case " $* " in
  *" --namespace "*|*" --all-namespaces "*) ;;        # caller chose a scope
  *) args+=("--all-namespaces") ;;
esac

echo "running: ./vdr ${args[*]} $*"
echo
set +e
"$repo_root/vdr" "${args[@]}" "$@"
status=$?
set -e

echo
echo "JSON report: $json_out"
echo "HTML report: $html_out"
if [ "$status" -ne 0 ]; then
  echo "vdr exited with status $status (some images may have failed to scan; see warnings above)."
fi
exit "$status"
