#!/usr/bin/env bash
# Logic of the pqc-scan GitHub Action (action.yml). Inputs arrive as
# environment variables, never interpolated into the script, so a crafted
# input cannot inject shell commands.
#
#   PQC_PATH, PQC_TLS, PQC_SSH, PQC_EXCLUDE, PQC_FAIL_ON, PQC_ONLY_NEW,
#   PQC_FORMAT, PQC_OUTPUT_DIR
# GitHub provides GITHUB_EVENT_NAME, GITHUB_BASE_REF, GITHUB_STEP_SUMMARY,
# GITHUB_OUTPUT and RUNNER_TEMP.
set -euo pipefail
set -f  # pass exclude globs through to the scanner

path="${PQC_PATH-.}"
fail_on="${PQC_FAIL_ON:-}"
format="${PQC_FORMAT:-html}"
out_dir="${PQC_OUTPUT_DIR:-pqc-scan-report}"
tmp="${RUNNER_TEMP:-$(mktemp -d)}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
outputs="${GITHUB_OUTPUT:-/dev/null}"
mkdir -p "$out_dir"

scan_args() {
  local root="$1"
  local -a args=()
  if [ -n "$path" ]; then args+=(--path "$root/$path"); fi
  for host in ${PQC_TLS:-}; do args+=(--tls "$host"); done
  for host in ${PQC_SSH:-}; do args+=(--ssh "$host"); done
  for pattern in ${PQC_EXCLUDE:-}; do args+=(--exclude "$pattern"); done
  if (( ${#args[@]} == 0 )); then return; fi
  printf '%s\0' "${args[@]}"
}

run_scan() {  # run_scan ROOT OUTPUT.json
  local -a args
  mapfile -d '' args < <(scan_args "$1")
  scan_status=0
  pqc-scan scan all "${args[@]}" --format json --out "$2" || scan_status=$?
  if (( scan_status != 0 && scan_status != 3 )); then return "$scan_status"; fi
}

head_json="$tmp/pqc-head.json"
run_scan "$PWD" "$head_json"

render_head() {
  local status=0
  pqc-scan report "$head_json" "$@" || status=$?
  if (( status == 3 && scan_status == 3 )); then return 0; fi
  return "$status"
}

case "$format" in
  json) ext=json ;;
  html) ext=html ;;
  cbom) ext=cdx.json ;;
  *) echo "::error::unsupported format '$format' (json, html or cbom)"; exit 2 ;;
esac
report="$out_dir/pqc-scan-report.$ext"
render_head --format "$format" --out "$report"
cp "$head_json" "$out_dir/pqc-scan.json"
render_head --format sarif --out "$out_dir/pqc-scan.sarif"

{
  echo "## pqc-scan"
  echo '```'
  COLUMNS=120 render_head
  echo '```'
} >> "$summary"

worst=$(python3 -c 'import json,sys
order=["PQ_SAFE","HYBRID","UNKNOWN","WEAKENED","VULNERABLE","BROKEN"]
risks=[f["risk"] for f in json.load(open(sys.argv[1]))["findings"]]
print(max(risks, key=order.index) if risks else "")' "$head_json")
{
  echo "report=$report"
  echo "json=$out_dir/pqc-scan.json"
  echo "sarif=$out_dir/pqc-scan.sarif"
  echo "worst-risk=$worst"
} >> "$outputs"

if (( scan_status == 3 )); then exit 3; fi

if [ -z "$fail_on" ]; then
  exit 0
fi

if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] && [ "${PQC_ONLY_NEW:-true}" = "true" ] \
   && [ -n "${GITHUB_BASE_REF:-}" ]; then
  base_dir="$tmp/pqc-base"
  git fetch --no-tags --depth=1 origin "$GITHUB_BASE_REF"
  git worktree add --detach "$base_dir" FETCH_HEAD >/dev/null
  base_json="$tmp/pqc-base.json"
  run_scan "$base_dir" "$base_json"
  git worktree remove --force "$base_dir"
  if (( scan_status == 3 )); then exit 3; fi
  {
    if [[ "${PQC_SCAN_LANG:-en}" == tr ]]; then
      echo "### \`$GITHUB_BASE_REF\` dalına göre değişiklikler"
    else
      echo "### Changes compared with \`$GITHUB_BASE_REF\`"
    fi
    echo '```'
    COLUMNS=120 pqc-scan diff "$base_json" "$head_json" || true
    echo '```'
  } >> "$summary"
  pqc-scan diff "$base_json" "$head_json" --format json --out "$out_dir/pqc-scan-diff.json"
  exec pqc-scan diff "$base_json" "$head_json" --fail-on "$fail_on" --out /dev/null
fi

exec pqc-scan report "$head_json" --fail-on "$fail_on" --out /dev/null
