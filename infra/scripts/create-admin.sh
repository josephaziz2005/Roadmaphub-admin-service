#!/usr/bin/env bash
# Creates the first administrator from ADMIN_* in infra/.env (owner: Joseph).
source "$(dirname "$0")/../lib.sh"
step "Admin account"
[ -f "$ROOT_DIR/infra/.env" ] && set -a && . <(sed 's/\r$//' "$ROOT_DIR/infra/.env") && set +a
(cd "$ROOT_DIR" && node scripts/create-admin.js)
