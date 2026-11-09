#!/usr/bin/env bash
# Проверка IPv4, портов, названий и идентификаторов Exit.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_VALIDATION_LOADED:-}" ]] && return 0
MEX_VALIDATION_LOADED=1

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

mex_valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o1="${BASH_REMATCH[1]}"
  local o2="${BASH_REMATCH[2]}"
  local o3="${BASH_REMATCH[3]}"
  local o4="${BASH_REMATCH[4]}"
  local o
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" =~ ^0[0-9]+$ ]] && return 1
    (( 10#$o >= 0 && 10#$o <= 255 )) || return 1
  done
  (( 10#$o1 == 0 )) && return 1
  (( 10#$o1 == 127 )) && return 1
  (( 10#$o1 >= 224 )) && return 1
  return 0
}

mex_valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [[ "$p" =~ ^0[0-9]+$ ]] && return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

mex_valid_name() {
  local n="$1"
  [[ -n "$n" ]] || return 1
  (( ${#n} <= 64 )) || return 1
  [[ "$n" != *$'\n'* && "$n" != *$'\r'* && "$n" != *$'\t'* ]] || return 1
  [[ "$n" == *\\* || "$n" == *\"* || "$n" == *\|* ]] && return 1
  if [[ "$n" =~ [[:cntrl:]] ]]; then
    return 1
  fi
  return 0
}

mex_valid_exit_id() {
  [[ "${1:-}" =~ ^exit-[1-9][0-9]*$ ]]
}

mex_valid_iface_name() {
  local name="$1"
  [[ "$name" =~ ^[A-Za-z0-9._:-]{1,15}$ ]]
}

mex_config_has_ip() {
  local ip="$1"
  local file="${2:-$MEX_CONFIG_FILE}"
  [[ -f "$file" ]] || return 1
  jq -e --arg ip "$ip" 'any(.exits[]?; .ip == $ip)' "$file" >/dev/null
}

mex_config_validate_file() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  jq -e '
    (.version == 1)
    and (.exits | type == "array")
    and all(
      .exits[]?;
      ((.id | type) == "string")
      and (.id | test("^exit-[1-9][0-9]*$"))
      and ((.name | type) == "string")
      and ((.ip | type) == "string")
      and ((.relay_port_443 | type) == "number")
      and ((.relay_port_8443 | type) == "number")
      and (.exit_port_443 == 443)
      and (.exit_port_8443 == 8443)
      and ((.status | type) == "string")
    )
  ' "$file" >/dev/null
}
