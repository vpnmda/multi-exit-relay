#!/usr/bin/env bash
# Резолв host Exit: литеральный IPv4 или A-записи DNS.
# Если адрес уже выбран и всё ещё есть в ответе, он сохраняется (не прыгает между A).
# При сбое DNS и наличии кэша того же host остаётся прежний IP, правила не снимаются.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_RESOLVE_LOADED:-}" ]] && return 0
MEX_RESOLVE_LOADED=1

# shellcheck source=validation.sh
source "$(dirname "${BASH_SOURCE[0]}")/validation.sh"

mex_norm_ctstate() {
  local raw="${1//\"/}"
  local -a parts=()
  local line out="" sorted
  [[ -n "$raw" ]] || return 0
  IFS=',' read -r -a parts <<<"$raw"
  sorted="$(printf '%s\n' "${parts[@]}" | LC_ALL=C sort)"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$line"
  done <<<"$sorted"
  printf '%s' "$out"
}

# Канонический вид правила iptables, одинаковый для argv и для строки iptables -S.
# Порядок флагов не важен. Маска /32, кавычки комментария и порядок ctstate сбрасываются.
mex_canon_from_args() {
  local proto="" dport="" sport="" comment="" jump="" to="" dest="" src="" ct=""
  local prev="" tok norm
  for tok in "$@"; do
    case "$prev" in
      -p) proto="$tok" ;;
      --dport) dport="$tok" ;;
      --sport) sport="$tok" ;;
      --comment) comment="${tok//\"/}" ;;
      -j) jump="$tok" ;;
      --to-destination) to="$tok" ;;
      -d) dest="${tok%%/*}"; dest="${dest//\"/}" ;;
      -s) src="${tok%%/*}"; src="${src//\"/}" ;;
      --ctstate)
        norm="$(mex_norm_ctstate "$tok")"
        ct="$norm"
        ;;
    esac
    prev="$tok"
  done
  printf 'p=%s;d=%s;s=%s;dport=%s;sport=%s;ct=%s;c=%s;j=%s;to=%s' \
    "$proto" "$dest" "$src" "$dport" "$sport" "$ct" "$comment" "$jump" "$to"
}

mex_dns_lookup_v4() {
  local host="$1"
  local out line ip
  local -a seen_ips=()
  if ! out="$(timeout "${MEX_RESOLVE_TIMEOUT:-5}" getent ahostsv4 "$host" 2>/dev/null)"; then
    return 1
  fi
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    ip="${line%% *}"
    mex_valid_ipv4 "$ip" || continue
    local seen=0 e
    if ((${#seen_ips[@]} > 0)); then
      for e in "${seen_ips[@]}"; do
        [[ "$e" == "$ip" ]] && seen=1
      done
    fi
    if (( seen == 0 )); then
      seen_ips+=("$ip")
    fi
  done <<<"$out"
  if ((${#seen_ips[@]} == 0)); then
    return 1
  fi
  printf '%s\n' "${seen_ips[@]}"
}

mex_select_resolved_ip() {
  local prev="$1"
  shift
  local ip
  if [[ -n "$prev" ]]; then
    for ip in "$@"; do
      if [[ "$ip" == "$prev" ]]; then
        printf '%s\n' "$prev"
        return 0
      fi
    done
  fi
  printf '%s\n' "$1"
}

# Печатает «id host ip stale». stale — true|false.
# Код 1: DNS не ответил и кэша для этого host нет.
mex_resolve_one() {
  local id="$1"
  local host="$2"
  local prev="" cached_host="" sel
  local -a ips=()
  if mex_valid_ipv4 "$host"; then
    printf '%s\t%s\t%s\t%s\n' "$id" "$host" "$host" "false"
    return 0
  fi
  if [[ -f "${MEX_STATE_FILE:-}" ]]; then
    prev="$(jq -r --arg id "$id" '.resolved[$id].selected // empty' "$MEX_STATE_FILE" 2>/dev/null || true)"
    cached_host="$(jq -r --arg id "$id" '.resolved[$id].host // empty' "$MEX_STATE_FILE" 2>/dev/null || true)"
    if [[ "$cached_host" != "$host" ]]; then
      prev=""
    fi
  fi
  local looked=""
  if looked="$(mex_dns_lookup_v4 "$host")"; then
    mapfile -t ips <<<"$looked"
    sel="$(mex_select_resolved_ip "$prev" "${ips[@]}")"
    printf '%s\t%s\t%s\t%s\n' "$id" "$host" "$sel" "false"
    return 0
  fi
  if [[ -n "$prev" && "$cached_host" == "$host" ]] && mex_valid_ipv4 "$prev"; then
    mex_warn "DNS для ${host} (${id}) не ответил. Оставляю прежний адрес ${prev}. Правила этого Exit не снимаются."
    printf '%s\t%s\t%s\t%s\n' "$id" "$host" "$prev" "true"
    return 0
  fi
  return 1
}

mex_state_store_resolved() {
  local lines_file="$1"
  local cur='{}'
  local now rows='[]'
  local id host ip stale
  mex_ensure_dirs
  if [[ -f "$MEX_STATE_FILE" ]] && jq -e . "$MEX_STATE_FILE" >/dev/null 2>&1; then
    cur="$(cat "$MEX_STATE_FILE")"
  fi
  now="$(mex_timestamp)"
  while IFS=$'\t' read -r id host ip stale; do
    [[ -n "${id:-}" ]] || continue
    # -n: jq не должен читать stdin цикла.
    rows="$(jq -nc \
      --argjson rows "$rows" \
      --arg id "$id" \
      --arg host "$host" \
      --arg ip "$ip" \
      --arg stale "$stale" \
      '$rows + [{id:$id, host:$host, ip:$ip, stale:($stale=="true")}]')"
  done <"$lines_file"
  jq -n \
    --argjson cur "$cur" \
    --argjson rows "$rows" \
    --arg now "$now" \
    '
      ($cur // {})
      | .version = 2
      | .updated_at = $now
      | .resolved = (
          reduce $rows[] as $r ({};
            .[$r.id] = {host: $r.host, selected: $r.ip, resolved_at: $now, stale: $r.stale}
          )
        )
    ' | mex_atomic_write "$MEX_STATE_FILE"
}

# Заполняет MEX_RESOLVED_IP / MEX_RESOLVED_STALE и файл $1 строками резолва.
mex_resolve_config_file() {
  local cfg="$1"
  local out="$2"
  local id host
  : >"$out"
  unset MEX_RESOLVED_IP MEX_RESOLVED_STALE
  declare -gA MEX_RESOLVED_IP=()
  declare -gA MEX_RESOLVED_STALE=()
  while IFS=$'\t' read -r id host; do
    [[ -n "${id:-}" ]] || continue
    local line rip stale
    if ! line="$(mex_resolve_one "$id" "$host")"; then
      mex_json_error 3 resolve_failed "Не удалось разрешить host ${host} для ${id}, и сохранённого адреса нет. Правила не изменены." || return $?
    fi
    printf '%s\n' "$line" >>"$out"
    IFS=$'\t' read -r _ _ rip stale <<<"$line"
    # Читает lib/iptables.sh при сборке правил.
    # shellcheck disable=SC2034
    MEX_RESOLVED_IP["$id"]="$rip"
    # shellcheck disable=SC2034
    MEX_RESOLVED_STALE["$id"]="$stale"
  done < <(jq -r '.exits[]? | [.id, .host] | @tsv' "$cfg")
  return 0
}
