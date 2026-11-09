#!/usr/bin/env bash
# Назначение внешних портов Relay.
# Exit N по умолчанию получает 443+(N-1)*10000 и 8443+(N-1)*10000.
# Занятая пара не перезаписывается: ищется другая свободная пара в диапазоне 1–65535.
# Порты уже настроенных Exit не меняются.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_PORTS_LOADED:-}" ]] && return 0
MEX_PORTS_LOADED=1

# shellcheck source=validation.sh
source "$(dirname "${BASH_SOURCE[0]}")/validation.sh"

mex_ports_reset() {
  local key
  # shellcheck disable=SC2178
  declare -gA MEX_PORT_OCCUPIED
  for key in "${!MEX_PORT_OCCUPIED[@]}"; do
    unset "MEX_PORT_OCCUPIED[$key]"
  done
}

mex_ports_mark() {
  local p
  # shellcheck disable=SC2178
  declare -gA MEX_PORT_OCCUPIED
  for p in "$@"; do
    [[ -n "$p" ]] || continue
    MEX_PORT_OCCUPIED["$p"]=1
  done
}

mex_ports_is_occupied() {
  local p="$1"
  [[ -n "${MEX_PORT_OCCUPIED[$p]+x}" ]]
}

mex_ports_pair_free() {
  local p1="$1"
  local p2="$2"
  mex_valid_port "$p1" || return 1
  mex_valid_port "$p2" || return 1
  (( p1 != p2 )) || return 1
  (( p1 != 22 && p2 != 22 )) || return 1
  mex_ports_is_occupied "$p1" && return 1
  mex_ports_is_occupied "$p2" && return 1
  return 0
}

mex_ports_default_pair() {
  local n="$1"
  local p1 p2
  [[ "$n" =~ ^[1-9][0-9]*$ ]] || return 1
  p1=$((443 + (n - 1) * 10000))
  p2=$((8443 + (n - 1) * 10000))
  if (( p1 < 1 || p1 > 65535 || p2 < 1 || p2 > 65535 )); then
    return 1
  fi
  printf '%s %s\n' "$p1" "$p2"
}

mex_ports_try_pair() {
  local p1="$1"
  local p2="$2"
  if mex_ports_pair_free "$p1" "$p2"; then
    printf '%s %s\n' "$p1" "$p2"
    return 0
  fi
  return 1
}

# Печатает «порт1 порт2» или возвращает 1, если свободной пары нет.
mex_ports_find_free_pair() {
  local n p1 p2 s step
  for n in 1 2 3 4 5 6; do
    p1=$((443 + (n - 1) * 10000))
    p2=$((8443 + (n - 1) * 10000))
    if mex_ports_try_pair "$p1" "$p2"; then
      return 0
    fi
  done
  for step in 1000 100 1; do
    local start=11443
    if (( step == 1 )); then
      start=1024
    fi
    for (( s = start; s <= 57535; s += step )); do
      p1=$s
      p2=$((s + 8000))
      (( p2 <= 65535 )) || continue
      if mex_ports_try_pair "$p1" "$p2"; then
        return 0
      fi
    done
  done
  return 1
}

mex_ports_scan_listeners() {
  local ss_out addr port
  if ! ss_out="$("${MEX_SS_BIN}" -H -lnt 2>/dev/null)"; then
    mex_warn "Команда ss не выполнилась. Локальные слушатели TCP не проверены."
    return 0
  fi
  while read -r _ _ _ addr _; do
    [[ -n "${addr:-}" ]] || continue
    port="${addr##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    mex_ports_mark "$port"
  done <<<"$ss_out"
}

mex_ports_scan_dnat() {
  local line
  if ! declare -F mex_iptables >/dev/null 2>&1; then
    mex_warn "Модуль правил iptables не загружен. Существующие DNAT не проверены."
    return 0
  fi
  while IFS= read -r line; do
    [[ "$line" == *"-j DNAT"* || "$line" == *"-j REDIRECT"* ]] || continue
    if [[ "$line" =~ --dport[[:space:]]+([0-9]+) ]]; then
      mex_ports_mark "${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ --dports[[:space:]]+([0-9,]+) ]]; then
      local part
      local -a parts=()
      IFS=',' read -r -a parts <<<"${BASH_REMATCH[1]}"
      for part in "${parts[@]}"; do
        mex_ports_mark "$part"
      done
    fi
  done < <(mex_iptables -t nat -S 2>/dev/null || true)
}

mex_ports_scan_config() {
  local p
  local file="${MEX_CONFIG_FILE:-}"
  [[ -n "$file" && -f "$file" ]] || return 0
  while IFS= read -r p; do
    [[ -n "$p" && "$p" != "null" ]] || continue
    mex_ports_mark "$p"
  done < <(jq -r '.exits[]? | .relay_port_443, .relay_port_8443' "$file" 2>/dev/null || true)
}

mex_ports_collect_all() {
  local -a planned=()
  mex_ports_reset
  mex_ports_mark 22
  mex_ports_scan_listeners
  mex_ports_scan_dnat
  mex_ports_scan_config
  if [[ -n "${MEX_PLANNED_PORTS:-}" ]]; then
    read -r -a planned <<<"$MEX_PLANNED_PORTS"
    if ((${#planned[@]} > 0)); then
      mex_ports_mark "${planned[@]}"
    fi
  fi
}
