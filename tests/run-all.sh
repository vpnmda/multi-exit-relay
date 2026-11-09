#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

echo "== bash -n =="
while IFS= read -r file; do
  bash -n "$file"
done < <(find "$root" -type f \( -name '*.sh' -o -name 'relay' -o -name 'install.sh' -o -name 'uninstall.sh' \) ! -path '*/.git/*')

echo "== shellcheck =="
if ! command -v shellcheck >/dev/null 2>&1; then
  printf '%s\n' "shellcheck не установлен" >&2
  exit 1
fi
shellcheck -x \
  install.sh uninstall.sh relay \
  lib/*.sh \
  tests/*.sh

echo "== unit =="
bash tests/test-forbidden.sh
bash tests/test-validation.sh
bash tests/test-ports.sh
bash tests/test-rules.sh
bash tests/test-contract.sh

echo "== help =="
bash install.sh --help | grep -q "non-interactive"
bash install.sh --version | grep -q "2.0.0"
bash relay help | grep -q -- "--json"
bash relay version | grep -q "2.0.0"
bash relay version --json | jq -e '.version == "2.0.0"' >/dev/null
bash uninstall.sh --help | grep -q "purge-config"

echo "== netns =="
bash tests/test-netns.sh

echo "== все проверки пройдены =="
