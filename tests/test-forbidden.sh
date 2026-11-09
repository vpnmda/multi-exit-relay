#!/usr/bin/env bash
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

scan_file() {
  local file="$1"
  local line no=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    no=$((no + 1))
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" == *"iptables-restore"* || "$line" == *"ip6tables-restore"* ]]; then
      fail "${file}:${no}: запрещено восстанавливать весь файрвол"
    fi
    if [[ "$line" == *"nft"* && "$line" == *"flush"* ]]; then
      fail "${file}:${no}: запрещён nft flush"
    fi
    if [[ "$line" == *"ufw disable"* || "$line" == *"ufw reset"* ]]; then
      fail "${file}:${no}: запрещено отключать UFW"
    fi
    if [[ "$line" =~ mex_iptables[^|]*[[:space:]]-F([[:space:]]|$) ]] || [[ "$line" =~ iptables[^|]*[[:space:]]-F([[:space:]]|$) ]]; then
      fail "${file}:${no}: запрещена полная очистка правил"
    fi
    if [[ "$line" =~ mex_iptables[^|]*[[:space:]]-P[[:space:]] ]] || [[ "$line" =~ [^a-z_]iptables[^|]*[[:space:]]-P[[:space:]] ]]; then
      fail "${file}:${no}: запрещено менять политику цепочки"
    fi
    if [[ "$line" =~ mex_iptables[^|]*[[:space:]]-X[[:space:]] ]]; then
      if [[ "$line" != *"-X MEX_PREROUTING"* && "$line" != *"-X MEX_POSTROUTING"* && "$line" != *"-X MEX_FORWARD"* ]]; then
        fail "${file}:${no}: -X разрешён только для собственных цепочек"
      fi
    fi
  done <"$file"
}

while IFS= read -r file; do
  scan_file "$file"
done < <(find "$root" -type f \( -name '*.sh' -o -name 'relay' -o -name 'install.sh' -o -name 'uninstall.sh' \) \
  ! -path '*/tests/*')

printf '%s\n' "OK forbidden"
