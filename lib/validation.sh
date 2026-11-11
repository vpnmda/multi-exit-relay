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

# Идентификатор Exit — slug: попадает в комментарий iptables mex:<id>.
# tcpmss и related-icmp заняты служебными правилами.
mex_valid_exit_id() {
  local id="${1:-}"
  [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || return 1
  [[ "$id" != "tcpmss" && "$id" != "related-icmp" ]] || return 1
  return 0
}

mex_valid_hostname() {
  local h="$1"
  (( ${#h} >= 1 && ${#h} <= 253 )) || return 1
  [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

# IPv4 или DNS-имя (ASCII, без завершающей точки). Невалидный «похожий на IP» адрес отвергается.
mex_valid_host() {
  local h="$1"
  if mex_valid_ipv4 "$h"; then
    return 0
  fi
  [[ "$h" =~ ^[0-9.]+$ ]] && return 1
  mex_valid_hostname "$h"
}

mex_valid_iface_name() {
  local name="$1"
  [[ "$name" =~ ^[A-Za-z0-9._:-]{1,15}$ ]]
}

mex_config_has_ip() {
  local ip="$1"
  local file="${2:-$MEX_CONFIG_FILE}"
  [[ -f "$file" ]] || return 1
  jq -e --arg ip "$ip" 'any(.exits[]?; .host == $ip or .ip == $ip)' "$file" >/dev/null
}

mex_config_v1_structure_ok() {
  local file="$1"
  jq -e '
    (.version == 1)
    and (.exits | type == "array")
    and all(
      .exits[]?;
      ((.id | type) == "string")
      and (.id | test("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"))
      and ((.name | type) == "string")
      and ((.ip | type) == "string")
      and ((.relay_port_443 | type) == "number")
      and ((.relay_port_8443 | type) == "number")
      and (.exit_port_443 == 443)
      and (.exit_port_8443 == 8443)
      and ((.status | type) == "string")
    )
  ' "$file" >/dev/null 2>&1
}

mex_config_v2_structure_ok() {
  local file="$1"
  jq -e '
    def port: type == "number" and (floor == .) and . >= 1 and . <= 65535;
    def slug:
      type == "string"
      and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
      and . != "tcpmss"
      and . != "related-icmp";
    (.version == 2)
    and (.exits | type == "array")
    and all(
      .exits[]?;
      (.id | slug)
      and ((.name | type) == "string")
      and ((.host | type) == "string")
      and ((.forwards | type) == "array")
      and all(
        .forwards[]?;
        ((.proto == "tcp") or (.proto == "udp"))
        and (.listen | port)
        and (.target | port)
      )
    )
  ' "$file" >/dev/null 2>&1
}

# 0 — коллизий нет. Дубли id и пары proto/listen (tcp и udp одного порта — не коллизия).
mex_config_v2_collisions() {
  local file="$1"
  jq -e '
    (([.exits[].id] | length) == ([.exits[].id] | unique | length))
    and (
      ([.exits[].forwards[]? | "\(.proto)/\(.listen)"] | length)
      == ([.exits[].forwards[]? | "\(.proto)/\(.listen)"] | unique | length)
    )
  ' "$file" >/dev/null 2>&1
}

# Печатает v2 JSON. v1 превращается в v2, v2 отдаётся как есть.
mex_config_normalize_json() {
  local file="$1"
  jq '
    if .version == 1 then
      .version = 2
      | .exits |= map(
          .host = (.host // .ip)
          | .forwards = (
              if (.forwards | type) == "array" then
                .forwards
              else
                [
                  {proto: "tcp", listen: .relay_port_443, target: (.exit_port_443 // 443)},
                  {proto: "tcp", listen: .relay_port_8443, target: (.exit_port_8443 // 8443)}
                ]
              end
            )
          | del(.ip, .relay_port_443, .relay_port_8443, .exit_port_443, .exit_port_8443)
        )
    else
      .
    end
  ' "$file"
}

# Классификация v2: пустой MEX_CONFIG_ERROR и код 0, иначе код ошибки и 1.
# Коды: config_invalid, config_collision, listen_reserved.
# shellcheck disable=SC2034
mex_config_classify_v2() {
  local file="$1"
  # Код читает relay apply, чтобы выбрать стабильный error в JSON.
  MEX_CONFIG_ERROR=""
  if ! mex_config_v2_structure_ok "$file"; then
    MEX_CONFIG_ERROR="config_invalid"
    return 1
  fi
  if ! mex_config_v2_collisions "$file"; then
    MEX_CONFIG_ERROR="config_collision"
    return 1
  fi
  if jq -e 'any(.exits[]?.forwards[]?; .proto == "tcp" and .listen == 22)' "$file" >/dev/null 2>&1; then
    MEX_CONFIG_ERROR="listen_reserved"
    return 1
  fi
  local id name host pub
  while IFS=$'\t' read -r id name host; do
    [[ -n "$id" ]] || continue
    if ! mex_valid_exit_id "$id" || ! mex_valid_name "$name" || ! mex_valid_host "$host"; then
      MEX_CONFIG_ERROR="config_invalid"
      return 1
    fi
  done < <(jq -r '.exits[]? | [.id, .name, .host] | @tsv' "$file")
  pub="$(jq -r '.public_ip // empty' "$file")"
  if [[ -n "$pub" ]] && jq -e --arg pub "$pub" 'any(.exits[]?; .host == $pub)' "$file" >/dev/null 2>&1; then
    MEX_CONFIG_ERROR="config_invalid"
    return 1
  fi
  return 0
}

mex_config_validate_file() {
  local file="$1"
  local ver
  [[ -f "$file" ]] || return 1
  ver="$(jq -r '.version // empty' "$file" 2>/dev/null || true)"
  case "$ver" in
    1) mex_config_v1_structure_ok "$file" ;;
    2) mex_config_classify_v2 "$file" ;;
    *) return 1 ;;
  esac
}

# Переписывает config.json в v2, если на диске v1. v2 не трогает.
mex_config_migrate_inplace() {
  local file="${1:-$MEX_CONFIG_FILE}"
  local ver tmp
  [[ -f "$file" ]] || return 1
  ver="$(jq -r '.version // empty' "$file" 2>/dev/null || true)"
  if [[ "$ver" == "2" ]]; then
    return 0
  fi
  if [[ "$ver" != "1" ]]; then
    return 1
  fi
  if ! mex_config_v1_structure_ok "$file"; then
    return 1
  fi
  tmp="$(mktemp)"
  if ! mex_config_normalize_json "$file" >"$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mex_config_classify_v2 "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$file"
}
