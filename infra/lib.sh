#!/usr/bin/env bash
# Shared settings for every infra script. Usage at the top of a script:  source "$(dirname "$0")/../lib.sh"
# Works in Git Bash on Windows and in Linux/macOS shells.
export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
# Floci accepts any keys; these are not secrets.
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_PAGER=""
export MSYS_NO_PATHCONV=1          # stop Git Bash turning /aws/... into C:/Program Files/Git/aws/...
export ACCOUNT_ID="000000000000"
export PREFIX="roadhub"

# awsl = aws pointed at Floci (same idea as Lab 8)
awsl() { aws --endpoint-url "$AWS_ENDPOINT_URL" --region "$AWS_REGION" "$@"; }

ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
info() { printf '  \033[36m...\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# make_table <name> <aws dynamodb create-table options...>   (skips a table that already exists)
make_table() {
  local name="$1"; shift
  if awsl dynamodb describe-table --table-name "$name" >/dev/null 2>&1; then
    ok "$name (already exists)"; return
  fi
  if ! awsl dynamodb create-table --table-name "$name" --billing-mode PAY_PER_REQUEST "$@" >/dev/null \
     || ! awsl dynamodb wait table-exists --table-name "$name"; then
    fail "$name could not be created (is Floci running? is the AWS CLI installed?)"
    return 1
  fi
  ok "$name created"
}

# gsi <indexName> <hashAttr> [rangeAttr]  ->  JSON for --global-secondary-indexes
gsi() {
  if [ -n "${3:-}" ]; then
    printf '{"IndexName":"%s","KeySchema":[{"AttributeName":"%s","KeyType":"HASH"},{"AttributeName":"%s","KeyType":"RANGE"}],"Projection":{"ProjectionType":"ALL"}}' "$1" "$2" "$3"
  else
    printf '{"IndexName":"%s","KeySchema":[{"AttributeName":"%s","KeyType":"HASH"}],"Projection":{"ProjectionType":"ALL"}}' "$1" "$2"
  fi
}

# point_in_time_recovery <table>   (backups; Floci may not support it, then it is only reported)
point_in_time_recovery() {
  awsl dynamodb update-continuous-backups --table-name "$1" \
    --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true >/dev/null 2>&1 \
    && ok "point-in-time recovery: $1" || info "point-in-time recovery not supported for $1"
}

# Repository root (the folder that contains package.json, infra/ ...)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT_DIR
