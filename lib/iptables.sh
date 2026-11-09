#!/usr/bin/env bash
# Правила проброса Multi-Exit Relay.
#
# Собственные цепочки:
#   nat/MEX_PREROUTING, nat/MEX_POSTROUTING, filter/MEX_FORWARD
# Переход из системных цепочек ставится один раз, в позицию 1.
# На каждый Exit — отдельные DNAT, FORWARD и MASQUERADE с комментарием mex:<id>.
# Глобальная MASQUERADE не используется. TCP и UDP пробрасываются одинаково:
# DNAT, FORWARD (NEW и ESTABLISHED,RELATED) и отдельный MASQUERADE на адрес Exit.
# SNI не меняется. Неизменённое правило не удаляется и не создаётся заново.
# TCPMSS --clamp-mss-to-pmtu добавляется один раз в mangle/FORWARD.
#
# MEX_DRY_RUN=1 не вызывает ядро: команды печатаются и исполняются симулятором.
# MEX_IPTABLES задаёт двоичный файл iptables (по умолчанию iptables).

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_IPTABLES_LOADED:-}" ]] && return 0
MEX_IPTABLES_LOADED=1

# shellcheck source=validation.sh
source "$(dirname "${BASH_SOURCE[0]}")/validation.sh"
# shellcheck source=resolve.sh
source "$(dirname "${BASH_SOURCE[0]}")/resolve.sh"

mex_spec_join() {
  local out="" a
  for a in "$@"; do
    if [[ -n "$out" ]]; then
      out+=" "
    fi
    out+="$a"
  done
  printf '%s' "$out"
}

mex_sim_path() {
  printf '%s/%s.db' "$MEX_SIM_DIR" "$1"
}

mex_sim_builtin() {
  case "$1" in
    INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING) return 0 ;;
    *) return 1 ;;
  esac
}

mex_sim_ensure_table() {
  local table="$1"
  local f
  mkdir -p "$MEX_SIM_DIR"
  f="$(mex_sim_path "$table")"
  [[ -f "$f" ]] && return 0
  case "$table" in
    filter)
      printf '%s\n' \
        $'P\tINPUT\tACCEPT' \
        $'P\tFORWARD\tACCEPT' \
        $'P\tOUTPUT\tACCEPT' \
        $'C\tINPUT' \
        $'C\tFORWARD' \
        $'C\tOUTPUT' >"$f"
      ;;
    nat)
      printf '%s\n' \
        $'P\tPREROUTING\tACCEPT' \
        $'P\tINPUT\tACCEPT' \
        $'P\tOUTPUT\tACCEPT' \
        $'P\tPOSTROUTING\tACCEPT' \
        $'C\tPREROUTING' \
        $'C\tINPUT' \
        $'C\tOUTPUT' \
        $'C\tPOSTROUTING' >"$f"
      ;;
    mangle)
      printf '%s\n' \
        $'P\tPREROUTING\tACCEPT' \
        $'P\tINPUT\tACCEPT' \
        $'P\tFORWARD\tACCEPT' \
        $'P\tOUTPUT\tACCEPT' \
        $'P\tPOSTROUTING\tACCEPT' \
        $'C\tPREROUTING' \
        $'C\tINPUT' \
        $'C\tFORWARD' \
        $'C\tOUTPUT' \
        $'C\tPOSTROUTING' >"$f"
      ;;
    *)
      printf 'Симулятор: неизвестная таблица %s\n' "$table" >&2
      return 2
      ;;
  esac
}

mex_sim_chain_exists() {
  local table="$1"
  local chain="$2"
  local line kind name
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name _ <<<"$line"
    if [[ "$kind" == "C" && "$name" == "$chain" ]]; then
      return 0
    fi
  done <"$(mex_sim_path "$table")"
  return 1
}

mex_sim_rewrite_filter() {
  local table="$1"
  local mode="$2"
  local chain="$3"
  local spec="$4"
  local pos="${5:-}"
  local f tmp line kind name rest
  local count=0 inserted=0 deleted=0
  f="$(mex_sim_path "$table")"
  tmp="$(mktemp)"
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name rest <<<"$line"
    if [[ "$kind" == "R" && "$name" == "$chain" ]]; then
      count=$((count + 1))
      case "$mode" in
        insert)
          if (( inserted == 0 && count == pos )); then
            printf 'R\t%s\t%s\n' "$chain" "$spec" >>"$tmp"
            inserted=1
          fi
          printf '%s\n' "$line" >>"$tmp"
          ;;
        delete-spec)
          if [[ "$deleted" == "0" && "$rest" == "$spec" ]]; then
            deleted=1
            continue
          fi
          printf '%s\n' "$line" >>"$tmp"
          ;;
        delete-num)
          if (( deleted == 0 && count == pos )); then
            deleted=1
            continue
          fi
          printf '%s\n' "$line" >>"$tmp"
          ;;
        *)
          printf '%s\n' "$line" >>"$tmp"
          ;;
      esac
    elif [[ "$mode" == "policy" && "$kind" == "P" && "$name" == "$chain" ]]; then
      printf 'P\t%s\t%s\n' "$chain" "$spec" >>"$tmp"
    elif [[ "$mode" == "drop-chain" && "$kind" == "C" && "$name" == "$chain" ]]; then
      continue
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$f"
  if [[ "$mode" == "insert" && "$inserted" == "0" ]]; then
    printf 'R\t%s\t%s\n' "$chain" "$spec" >>"$tmp"
    inserted=1
  fi
  mv -f "$tmp" "$f"
  case "$mode" in
    delete-spec|delete-num)
      (( deleted == 1 )) || return 1
      ;;
    insert)
      (( inserted == 1 )) || return 1
      ;;
  esac
  return 0
}

mex_sim_new_chain() {
  local table="$1" chain="$2"
  if mex_sim_builtin "$chain" || mex_sim_chain_exists "$table" "$chain"; then
    printf '%s\n' "iptables: Chain already exists." >&2
    return 1
  fi
  printf 'C\t%s\n' "$chain" >>"$(mex_sim_path "$table")"
}

mex_sim_append() {
  local table="$1" chain="$2" spec="$3"
  if ! mex_sim_chain_exists "$table" "$chain"; then
    printf '%s\n' "iptables: No chain/target/match by that name." >&2
    return 1
  fi
  printf 'R\t%s\t%s\n' "$chain" "$spec" >>"$(mex_sim_path "$table")"
}

mex_sim_rule_count() {
  local table="$1" chain="$2"
  local line kind name n=0
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name _ <<<"$line"
    if [[ "$kind" == "R" && "$name" == "$chain" ]]; then
      n=$((n + 1))
    fi
  done <"$(mex_sim_path "$table")"
  printf '%s\n' "$n"
}

mex_sim_has_spec() {
  local table="$1" chain="$2" spec="$3"
  local line kind name rest
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name rest <<<"$line"
    if [[ "$kind" == "R" && "$name" == "$chain" && "$rest" == "$spec" ]]; then
      return 0
    fi
  done <"$(mex_sim_path "$table")"
  return 1
}

mex_sim_chain_referenced() {
  local table="$1" chain="$2"
  local line kind _rest
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind _ _rest <<<"$line"
    if [[ "$kind" == "R" && "$_rest" == *"-j ${chain}"* ]]; then
      return 0
    fi
  done <"$(mex_sim_path "$table")"
  return 1
}

mex_sim_delete_chain() {
  local table="$1" chain="${2:-}"
  if [[ -z "$chain" ]]; then
    printf '%s\n' "iptables: отказ симулятора удалять все цепочки сразу." >&2
    return 2
  fi
  if mex_sim_builtin "$chain"; then
    printf '%s\n' "iptables: Can't delete builtin chain ${chain}." >&2
    return 1
  fi
  if ! mex_sim_chain_exists "$table" "$chain"; then
    printf '%s\n' "iptables: No chain/target/match by that name." >&2
    return 1
  fi
  if [[ "$(mex_sim_rule_count "$table" "$chain")" != "0" ]]; then
    printf '%s\n' "iptables: chain ${chain} is not empty." >&2
    return 1
  fi
  if mex_sim_chain_referenced "$table" "$chain"; then
    printf '%s\n' "iptables: Too many links." >&2
    return 1
  fi
  mex_sim_rewrite_filter "$table" drop-chain "$chain" "" || return 1
}

mex_sim_list() {
  local table="$1" chain="$2"
  local line kind name rest n=0 comment
  if ! mex_sim_chain_exists "$table" "$chain"; then
    printf '%s\n' "iptables: No chain/target/match by that name." >&2
    return 1
  fi
  printf 'Chain %s (0 references)\n' "$chain"
  printf '%s\n' "num  target     prot opt source               destination"
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name rest <<<"$line"
    [[ "$kind" == "R" && "$name" == "$chain" ]] || continue
    n=$((n + 1))
    comment=""
    if [[ "$rest" =~ --comment[[:space:]]+([^[:space:]]+) ]]; then
      comment="${BASH_REMATCH[1]}"
      comment="${comment//\"/}"
    fi
    printf '%d    TARGET  tcp  --  0.0.0.0/0            0.0.0.0/0            /* %s */\n' "$n" "$comment"
  done <"$(mex_sim_path "$table")"
}

mex_sim_save_chain() {
  local table="$1" chain="$2"
  local line kind name rest policy=""
  if ! mex_sim_chain_exists "$table" "$chain"; then
    printf '%s\n' "iptables: No chain/target/match by that name." >&2
    return 1
  fi
  if mex_sim_builtin "$chain"; then
    while IFS= read -r line || [[ -n "${line:-}" ]]; do
      IFS=$'\t' read -r kind name rest <<<"$line"
      if [[ "$kind" == "P" && "$name" == "$chain" ]]; then
        policy="$rest"
      fi
    done <"$(mex_sim_path "$table")"
    printf -- '-P %s %s\n' "$chain" "$policy"
  else
    printf -- '-N %s\n' "$chain"
  fi
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name rest <<<"$line"
    if [[ "$kind" == "R" && "$name" == "$chain" ]]; then
      printf -- '-A %s %s\n' "$chain" "$rest"
    fi
  done <"$(mex_sim_path "$table")"
}

mex_sim_save_all() {
  local table="$1"
  local line kind name rest
  local -a chains=()
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name rest <<<"$line"
    case "$kind" in
      P) printf -- '-P %s %s\n' "$name" "$rest" ;;
      C) chains+=("$name") ;;
    esac
  done <"$(mex_sim_path "$table")"
  local chain
  for chain in "${chains[@]}"; do
    if ! mex_sim_builtin "$chain"; then
      printf -- '-N %s\n' "$chain"
    fi
  done
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    IFS=$'\t' read -r kind name rest <<<"$line"
    if [[ "$kind" == "R" ]]; then
      printf -- '-A %s %s\n' "$name" "$rest"
    fi
  done <"$(mex_sim_path "$table")"
}

mex_sim_dispatch() {
  local table="filter"
  local -a args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--table)
        table="${2:-}"
        shift 2
        ;;
      -w|--wait)
        shift
        if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then
          shift
        fi
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done
  mex_sim_ensure_table "$table" || return $?
  local cmd="${args[0]:-}"
  local chain spec pos idx total
  case "$cmd" in
    -N)
      [[ -n "${args[1]:-}" ]] || return 2
      mex_sim_new_chain "$table" "${args[1]}"
      ;;
    -X)
      mex_sim_delete_chain "$table" "${args[1]:-}"
      ;;
    -F)
      printf '%s\n' "iptables: симулятор отклоняет полную очистку таблицы." >&2
      return 2
      ;;
    -P)
      chain="${args[1]:-}"
      spec="${args[2]:-}"
      if ! mex_sim_builtin "$chain"; then
        printf '%s\n' "iptables: can't set policy on ${chain}." >&2
        return 1
      fi
      mex_sim_rewrite_filter "$table" policy "$chain" "$spec"
      ;;
    -A)
      chain="${args[1]:-}"
      spec="$(mex_spec_join "${args[@]:2}")"
      mex_sim_append "$table" "$chain" "$spec"
      ;;
    -I)
      chain="${args[1]:-}"
      idx=2
      pos=1
      if [[ "${args[2]:-}" =~ ^[0-9]+$ ]]; then
        pos="${args[2]}"
        idx=3
      fi
      spec="$(mex_spec_join "${args[@]:idx}")"
      total="$(mex_sim_rule_count "$table" "$chain")"
      if (( pos < 1 || pos > total + 1 )); then
        printf '%s\n' "iptables: Index of insertion too big." >&2
        return 1
      fi
      mex_sim_rewrite_filter "$table" insert "$chain" "$spec" "$pos"
      ;;
    -D)
      chain="${args[1]:-}"
      if [[ "${args[2]:-}" =~ ^[0-9]+$ && ${#args[@]} -eq 3 ]]; then
        mex_sim_rewrite_filter "$table" delete-num "$chain" "" "${args[2]}" || {
          printf '%s\n' "iptables: Index of deletion too big." >&2
          return 1
        }
      else
        spec="$(mex_spec_join "${args[@]:2}")"
        mex_sim_rewrite_filter "$table" delete-spec "$chain" "$spec" || {
          printf '%s\n' "iptables: Bad rule (does a matching rule exist in that chain?)." >&2
          return 1
        }
      fi
      ;;
    -C)
      chain="${args[1]:-}"
      spec="$(mex_spec_join "${args[@]:2}")"
      if ! mex_sim_chain_exists "$table" "$chain"; then
        printf '%s\n' "iptables: No chain/target/match by that name." >&2
        return 1
      fi
      if ! mex_sim_has_spec "$table" "$chain" "$spec"; then
        printf '%s\n' "iptables: Bad rule (does a matching rule exist in that chain?)." >&2
        return 1
      fi
      ;;
    -S)
      if [[ -n "${args[1]:-}" ]]; then
        mex_sim_save_chain "$table" "${args[1]}"
      else
        mex_sim_save_all "$table"
      fi
      ;;
    -L)
      chain=""
      local item
      for item in "${args[@]:1}"; do
        case "$item" in
          -n|-v|-x|--line-numbers|--exact) ;;
          -*) ;;
          *) chain="$item" ;;
        esac
      done
      if [[ -z "$chain" ]]; then
        printf '%s\n' "iptables: симулятору для -L нужно имя цепочки." >&2
        return 2
      fi
      mex_sim_list "$table" "$chain"
      ;;
    *)
      printf 'Симулятор: неизвестная команда %s\n' "$cmd" >&2
      return 2
      ;;
  esac
}

mex_iptables() {
  local rc=0
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    if [[ -z "${MEX_SIM_DIR:-}" ]]; then
      MEX_SIM_DIR="${TMPDIR:-/tmp}/mex-sim-$$"
    fi
    mex_dry_log iptables "$@"
    mex_sim_dispatch "$@" || rc=$?
    return "$rc"
  fi
  "${MEX_IPTABLES}" -w 5 "$@"
}

mex_iptables_list() {
  local table="$1"
  local chain="$2"
  LC_ALL=C mex_iptables -t "$table" -L "$chain" -n --line-numbers 2>/dev/null || true
}

mex_iptables_chain_exists() {
  local table="$1"
  local chain="$2"
  mex_iptables -t "$table" -S "$chain" >/dev/null 2>&1
}

mex_iptables_ensure_chain() {
  local table="$1"
  local chain="$2"
  if mex_iptables_chain_exists "$table" "$chain"; then
    return 0
  fi
  mex_iptables -t "$table" -N "$chain"
}

mex_iptables_ensure_jump() {
  local table="$1"
  local from="$2"
  local to="$3"
  if mex_iptables -t "$table" -C "$from" -j "$to" >/dev/null 2>&1; then
    return 0
  fi
  mex_iptables -t "$table" -I "$from" 1 -j "$to"
}

mex_iptables_ensure_rule() {
  local table="$1"
  local chain="$2"
  shift 2
  if mex_iptables -t "$table" -C "$chain" "$@" >/dev/null 2>&1; then
    return 0
  fi
  mex_iptables -t "$table" -A "$chain" "$@"
}

mex_iptables_delete_comment() {
  local table="$1"
  local chain="$2"
  local comment="$3"
  local line
  local -a nums=()
  while IFS= read -r line; do
    [[ "$line" == *"/* ${comment} */"* ]] || continue
    if [[ "$line" =~ ^([0-9]+) ]]; then
      nums+=("${BASH_REMATCH[1]}")
    fi
  done < <(mex_iptables_list "$table" "$chain")
  local i
  for (( i = ${#nums[@]} - 1; i >= 0; i-- )); do
    mex_iptables -t "$table" -D "$chain" "${nums[$i]}"
  done
}

mex_iptables_ensure_tcpmss() {
  local -a rule=(
    -p tcp --tcp-flags "SYN,RST" SYN
    -m comment --comment mex:tcpmss
    -j TCPMSS --clamp-mss-to-pmtu
  )
  if [[ "${MEX_TCPMSS_UNAVAILABLE:-0}" == "1" ]]; then
    return 1
  fi
  if mex_iptables -t mangle -C FORWARD "${rule[@]}" >/dev/null 2>&1; then
    return 0
  fi
  if mex_iptables -t mangle -A FORWARD "${rule[@]}" >/dev/null 2>&1; then
    mex_log INFO "Добавлено TCPMSS --clamp-mss-to-pmtu."
    return 0
  fi
  MEX_TCPMSS_UNAVAILABLE=1
  mex_warn "Не удалось добавить TCPMSS --clamp-mss-to-pmtu. Ядро не поддерживает цель TCPMSS. Проброс TCP продолжит работать, но MSS не будет зажиматься. На обычном ядре Ubuntu 22.04/24.04 эта цель доступна."
  return 1
}

mex_iptables_ensure_base() {
  mex_iptables_ensure_chain nat MEX_PREROUTING || return 1
  mex_iptables_ensure_chain nat MEX_POSTROUTING || return 1
  mex_iptables_ensure_chain filter MEX_FORWARD || return 1
  mex_iptables_ensure_jump nat PREROUTING MEX_PREROUTING || return 1
  mex_iptables_ensure_jump nat POSTROUTING MEX_POSTROUTING || return 1
  mex_iptables_ensure_jump filter FORWARD MEX_FORWARD || return 1
  mex_iptables_ensure_tcpmss || true
  return 0
}

mex_listen_local_busy() {
  local proto="$1"
  local port="$2"
  local -a flags=(-H -lnt)
  local out addr p
  if [[ "$proto" == "udp" ]]; then
    flags=(-H -lnu)
  fi
  out="$("${MEX_SS_BIN}" "${flags[@]}" 2>/dev/null || true)"
  while read -r _ _ _ addr _; do
    [[ -n "${addr:-}" ]] || continue
    p="${addr##*:}"
    [[ "$p" == "$port" ]] && return 0
  done <<<"$out"
  return 1
}

mex_listen_foreign_dnat() {
  local proto="$1"
  local port="$2"
  local line dport
  while IFS= read -r line; do
    [[ "$line" == "-A "* ]] || continue
    [[ "$line" == "-A MEX_"* ]] && continue
    [[ "$line" == *"mex:"* ]] && continue
    [[ "$line" == *"-j DNAT"* || "$line" == *"-j REDIRECT"* ]] || continue
    if [[ "$line" == *"-p udp"* && "$proto" != "udp" ]]; then
      continue
    fi
    if [[ "$line" == *"-p tcp"* && "$proto" != "tcp" ]]; then
      continue
    fi
    if [[ "$line" =~ --dport[[:space:]]+([0-9]+) ]]; then
      dport="${BASH_REMATCH[1]}"
      [[ "$dport" == "$port" ]] && return 0
    fi
  done < <(mex_iptables -t nat -S 2>/dev/null || true)
  return 1
}

mex_ip_assigned_locally() {
  local ip="$1"
  local out
  out="$("${MEX_IP_BIN}" -4 -o addr show 2>/dev/null || true)"
  [[ -n "$out" ]] || return 1
  grep -Eq "(^|[[:space:]])${ip}/" <<<"$out"
}

mex_apply_check_listen() {
  local cfg="$1"
  local id proto listen
  while IFS=$'\t' read -r id proto listen; do
    [[ -n "$id" ]] || continue
    if mex_listen_local_busy "$proto" "$listen"; then
      mex_json_error 3 listen_busy "Порт ${proto}/${listen} занят локальным процессом. Правила не изменены." || return $?
    fi
    if mex_listen_foreign_dnat "$proto" "$listen"; then
      mex_json_error 3 listen_foreign_dnat "Чужой DNAT уже занимает ${proto}/${listen}. Правила не изменены." || return $?
    fi
  done < <(jq -r '.exits[] | .id as $id | .forwards[]? | [$id, .proto, (.listen|tostring)] | @tsv' "$cfg")
  return 0
}

mex_desired_add() {
  local table="$1"
  local chain="$2"
  shift 2
  local canon key line a
  canon="$(mex_canon_from_args "$@")"
  key="${table}|${chain}|${canon}"
  if [[ -n "${MEX_DESIRED_SEEN[$key]+x}" ]]; then
    return 0
  fi
  MEX_DESIRED_SEEN["$key"]=1
  line="${table}"$'\t'"${chain}"
  for a in "$@"; do
    line+=$'\t'"$a"
  done
  printf '%s\n' "$line" >>"$MEX_DESIRED_FILE"
}

mex_desired_build() {
  local cfg="$1"
  local id proto listen target ip c n=0
  MEX_DESIRED_FILE="$(mktemp)"
  unset MEX_DESIRED_SEEN
  declare -gA MEX_DESIRED_SEEN=()
  : >"$MEX_DESIRED_FILE"
  while IFS=$'\t' read -r id proto listen target; do
    [[ -n "$id" ]] || continue
    ip="${MEX_RESOLVED_IP[$id]:-}"
    if ! mex_valid_ipv4 "$ip"; then
      mex_json_error 3 resolve_failed "Нет IPv4-адреса для ${id}. Правила не изменены." || return $?
    fi
    if ! mex_valid_port "$listen" || ! mex_valid_port "$target"; then
      mex_json_error 2 config_invalid "Некорректный порт у ${id}. Правила не изменены." || return $?
    fi
    if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
      mex_json_error 2 config_invalid "Некорректный протокол у ${id}. Правила не изменены." || return $?
    fi
    n=$((n + 1))
    c="mex:${id}"
    mex_desired_add nat MEX_PREROUTING \
      -p "$proto" --dport "$listen" -m comment --comment "$c" -j DNAT --to-destination "${ip}:${target}"
    mex_desired_add nat MEX_POSTROUTING \
      -p "$proto" -d "$ip" --dport "$target" -m comment --comment "$c" -j MASQUERADE
    mex_desired_add filter MEX_FORWARD \
      -p "$proto" -d "$ip" --dport "$target" -m conntrack --ctstate NEW -m comment --comment "$c" -j ACCEPT
    mex_desired_add filter MEX_FORWARD \
      -p "$proto" -d "$ip" --dport "$target" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT
    mex_desired_add filter MEX_FORWARD \
      -p "$proto" -s "$ip" --sport "$target" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT
  done < <(jq -r '.exits[] | .id as $id | .forwards[]? | [$id, .proto, (.listen|tostring), (.target|tostring)] | @tsv' "$cfg")
  if (( n > 0 )); then
    mex_desired_add filter MEX_FORWARD \
      -p icmp -m conntrack --ctstate RELATED -m comment --comment mex:related-icmp -j ACCEPT
  fi
  return 0
}

mex_iptables_delete_stale() {
  local table="$1"
  local chain="$2"
  local -a rests=() stale=() args=()
  local line rest i canon comment key n j
  if ! mex_iptables_chain_exists "$table" "$chain"; then
    return 0
  fi
  while IFS= read -r line; do
    [[ "$line" == "-A ${chain} "* ]] || continue
    rest="${line#-A "${chain}" }"
    rests+=("$rest")
  done < <(mex_iptables -t "$table" -S "$chain" 2>/dev/null || true)
  if ((${#rests[@]} == 0)); then
    return 0
  fi
  for i in "${!rests[@]}"; do
    read -r -a args <<<"${rests[$i]}"
    canon="$(mex_canon_from_args "${args[@]}")"
    comment="${canon#*;c=}"
    comment="${comment%%;j=*}"
    [[ "$comment" == mex:* ]] || continue
    key="${table}|${chain}|${canon}"
    if [[ -n "${MEX_WANT_CANON[$key]+x}" ]]; then
      continue
    fi
    stale+=("$((i + 1))")
  done
  n="${#stale[@]}"
  for (( j = n - 1; j >= 0; j-- )); do
    if ! mex_iptables -t "$table" -D "$chain" "${stale[$j]}" >/dev/null; then
      mex_json_error 3 apply_failed "Не удалось удалить устаревшее правило ${chain} №${stale[$j]}." || return $?
    fi
    MEX_RULES_REMOVED=$((MEX_RULES_REMOVED + 1))
  done
  return 0
}

mex_iptables_reconcile() {
  local cfg="$1"
  local table chain spec_rest canon key
  local -a args=()
  mex_desired_build "$cfg" || return $?
  unset MEX_WANT_CANON
  declare -gA MEX_WANT_CANON=()
  MEX_RULES_ADDED=0
  MEX_RULES_REMOVED=0
  MEX_RULES_UNCHANGED=0
  local add_failed=0
  while IFS=$'\t' read -r table chain spec_rest; do
    [[ -n "$table" ]] || continue
    IFS=$'\t' read -r -a args <<<"$spec_rest"
    canon="$(mex_canon_from_args "${args[@]}")"
    key="${table}|${chain}|${canon}"
    MEX_WANT_CANON["$key"]=1
    if mex_iptables -t "$table" -C "$chain" "${args[@]}" >/dev/null 2>&1; then
      MEX_RULES_UNCHANGED=$((MEX_RULES_UNCHANGED + 1))
    else
      if ! mex_iptables -t "$table" -A "$chain" "${args[@]}" >/dev/null; then
        add_failed=1
        break
      fi
      MEX_RULES_ADDED=$((MEX_RULES_ADDED + 1))
    fi
  done <"$MEX_DESIRED_FILE"
  rm -f "$MEX_DESIRED_FILE"
  if (( add_failed == 1 )); then
    mex_json_error 3 apply_failed "Не удалось добавить правило проброса." || return $?
  fi
  mex_iptables_delete_stale nat MEX_PREROUTING || return $?
  mex_iptables_delete_stale nat MEX_POSTROUTING || return $?
  mex_iptables_delete_stale filter MEX_FORWARD || return $?
  return 0
}

# Печатает «dnat masq forward» из 0/1. Не меняет правила.
mex_iptables_forward_flags() {
  local id="$1" ip="$2" proto="$3" listen="$4" target="$5"
  local c="mex:${id}"
  local dnat=0 masq=0 fwd=0
  if mex_iptables -t nat -C MEX_PREROUTING \
    -p "$proto" --dport "$listen" -m comment --comment "$c" -j DNAT --to-destination "${ip}:${target}" >/dev/null 2>&1; then
    dnat=1
  fi
  if mex_iptables -t nat -C MEX_POSTROUTING \
    -p "$proto" -d "$ip" --dport "$target" -m comment --comment "$c" -j MASQUERADE >/dev/null 2>&1; then
    masq=1
  fi
  if mex_iptables -C MEX_FORWARD \
    -p "$proto" -d "$ip" --dport "$target" -m conntrack --ctstate NEW -m comment --comment "$c" -j ACCEPT >/dev/null 2>&1 \
    && mex_iptables -C MEX_FORWARD \
    -p "$proto" -d "$ip" --dport "$target" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT >/dev/null 2>&1 \
    && mex_iptables -C MEX_FORWARD \
    -p "$proto" -s "$ip" --sport "$target" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT >/dev/null 2>&1; then
    fwd=1
  fi
  printf '%s %s %s\n' "$dnat" "$masq" "$fwd"
}

mex_dnat_destination_ip() {
  local id="$1" proto="$2" listen="$3" target="$4"
  local line ip
  while IFS= read -r line; do
    [[ "$line" == *"-j DNAT"* ]] || continue
    [[ "$line" == *"-p ${proto} "* ]] || continue
    [[ "$line" == *"comment mex:${id} "* || "$line" == *"comment mex:${id}" || "$line" == *"comment \"mex:${id}\""* ]] || continue
    [[ "$line" == *"--dport ${listen} "* || "$line" == *"--dport ${listen}" ]] || continue
    if [[ "$line" =~ --to-destination[[:space:]]+([0-9.]+):([0-9]+) ]]; then
      [[ "${BASH_REMATCH[2]}" == "$target" ]] || continue
      ip="${BASH_REMATCH[1]}"
      printf '%s\n' "$ip"
      return 0
    fi
  done < <(mex_iptables -t nat -S MEX_PREROUTING 2>/dev/null || true)
  return 1
}

mex_dnat_counters() {
  local id="$1" proto="$2" listen="$3" ip="$4" target="$5"
  local line
  while IFS= read -r line; do
    [[ "$line" == *"/* mex:${id} */"* ]] || continue
    [[ "$line" == *"${proto} dpt:${listen} "* ]] || continue
    [[ "$line" == *"to:${ip}:${target}" ]] || continue
    if [[ "$line" =~ ^[[:space:]]*([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)[[:space:]] ]]; then
      printf '%s %s\n' "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
      return 0
    fi
  done < <(LC_ALL=C mex_iptables -t nat -L MEX_PREROUTING -n -v -x --line-numbers 2>/dev/null || true)
  return 1
}

mex_iptables_remove_exit() {
  local id="$1"
  local c="mex:${id}"
  mex_valid_exit_id "$id" || {
    mex_fail "Некорректный идентификатор Exit: ${id}" || true
    return 1
  }
  mex_iptables_delete_comment nat MEX_PREROUTING "$c" || return 1
  mex_iptables_delete_comment nat MEX_POSTROUTING "$c" || return 1
  mex_iptables_delete_comment filter MEX_FORWARD "$c" || return 1
}

mex_iptables_remove_jump() {
  local table="$1" from="$2" to="$3"
  local i
  for (( i = 0; i < 20; i++ )); do
    if ! mex_iptables -t "$table" -C "$from" -j "$to" >/dev/null 2>&1; then
      return 0
    fi
    mex_iptables -t "$table" -D "$from" -j "$to" || return 1
  done
  mex_fail "Не удалось удалить переход ${from} -> ${to}." || true
  return 1
}

mex_iptables_empty_rules() {
  local table="$1" chain="$2"
  local guard=0 line num
  while (( guard < 10000 )); do
    guard=$((guard + 1))
    num=""
    while IFS= read -r line; do
      if [[ "$line" =~ ^([0-9]+) ]]; then
        num="${BASH_REMATCH[1]}"
      fi
    done < <(mex_iptables_list "$table" "$chain")
    [[ -n "$num" ]] || break
    mex_iptables -t "$table" -D "$chain" "$num" || return 1
  done
}

mex_iptables_empty_own_chain() {
  local table="$1" chain="$2"
  case "${table}:${chain}" in
    nat:MEX_PREROUTING|nat:MEX_POSTROUTING|filter:MEX_FORWARD) ;;
    *)
      mex_fail "Отказ удалять чужую цепочку ${table}/${chain}." || true
      return 1
      ;;
  esac
  if ! mex_iptables_chain_exists "$table" "$chain"; then
    return 0
  fi
  mex_iptables_empty_rules "$table" "$chain" || return 1
  case "${table}:${chain}" in
    nat:MEX_PREROUTING) mex_iptables -t nat -X MEX_PREROUTING ;;
    nat:MEX_POSTROUTING) mex_iptables -t nat -X MEX_POSTROUTING ;;
    filter:MEX_FORWARD) mex_iptables -t filter -X MEX_FORWARD ;;
  esac
}

mex_iptables_comments_in_chain() {
  local table="$1" chain="$2"
  local out
  out="$(mex_iptables_list "$table" "$chain")"
  printf '%s\n' "$out" | grep -oE 'mex:exit-[0-9]+' || true
}

mex_iptables_drop_orphans() {
  local -A keep=()
  local id comment table chain
  while IFS= read -r id; do
    [[ -n "$id" ]] && keep["$id"]=1
  done < <(jq -r '.exits[]?.id' "$MEX_CONFIG_FILE" 2>/dev/null || true)
  local spec
  for spec in "nat MEX_PREROUTING" "nat MEX_POSTROUTING" "filter MEX_FORWARD"; do
    read -r table chain <<<"$spec"
    while IFS= read -r comment; do
      [[ -n "$comment" ]] || continue
      id="${comment#mex:}"
      if [[ -z "${keep[$id]+x}" ]]; then
        mex_iptables_delete_comment "$table" "$chain" "$comment" || return 1
      fi
    done < <(mex_iptables_comments_in_chain "$table" "$chain" | sort -u)
  done
}

mex_iptables_apply_exit_from_config() {
  mex_iptables_apply_config
}

mex_iptables_apply_config() {
  local cfg="$MEX_CONFIG_FILE"
  local ver err pub id ip resolved rc
  if [[ ! -f "$cfg" ]]; then
    mex_json_error 2 config_missing "Нет файла конфигурации ${cfg}." || return $?
  fi
  ver="$(jq -r '.version // empty' "$cfg" 2>/dev/null || true)"
  if [[ "$ver" == "1" ]]; then
    if ! mex_config_migrate_inplace "$cfg"; then
      mex_json_error 2 config_invalid "Не удалось перевести ${cfg} со схемы v1 на v2. Правила не изменены." || return $?
    fi
  fi
  if ! mex_config_classify_v2 "$cfg"; then
    err="${MEX_CONFIG_ERROR:-config_invalid}"
    case "$err" in
      config_collision)
        mex_json_error 2 config_collision "В конфигурации совпадают id или пара протокол/порт прослушивания. Один и тот же порт можно занять отдельно для tcp и udp. Правила не изменены." || return $?
        ;;
      listen_reserved)
        mex_json_error 2 listen_reserved "TCP-порт 22 на Relay занимать нельзя: DNAT перехватил бы SSH. Правила не изменены." || return $?
        ;;
      *)
        mex_json_error 2 config_invalid "Файл ${cfg} не прошёл проверку схемы v2. Правила не изменены." || return $?
        ;;
    esac
  fi
  resolved="$(mktemp)"
  mex_resolve_config_file "$cfg" "$resolved"
  rc=$?
  if (( rc != 0 )); then
    rm -f "$resolved"
    return "$rc"
  fi
  pub="$(jq -r '.public_ip // empty' "$cfg")"
  if ((${#MEX_RESOLVED_IP[@]} > 0)); then
    for id in "${!MEX_RESOLVED_IP[@]}"; do
      ip="${MEX_RESOLVED_IP[$id]}"
      if [[ -n "$pub" && "$ip" == "$pub" ]]; then
        rm -f "$resolved"
        mex_json_error 2 host_is_local "Адрес ${ip} совпадает с публичным IP Relay. Правила не изменены." || return $?
      fi
      if mex_ip_assigned_locally "$ip"; then
        rm -f "$resolved"
        mex_json_error 2 host_is_local "Адрес ${ip} назначен локальному интерфейсу Relay. Правила не изменены." || return $?
      fi
    done
  fi
  mex_apply_check_listen "$cfg"
  rc=$?
  if (( rc != 0 )); then
    rm -f "$resolved"
    return "$rc"
  fi
  if ! mex_iptables_ensure_base; then
    rm -f "$resolved"
    mex_json_error 3 apply_failed "Не удалось подготовить цепочки Multi-Exit Relay. Чужие правила не изменялись." || return $?
  fi
  if ! mex_iptables_reconcile "$cfg"; then
    rc=$?
    rm -f "$resolved"
    return "$rc"
  fi
  mex_state_store_resolved "$resolved" || true
  rm -f "$resolved"
  return 0
}

mex_iptables_uninstall() {
  mex_iptables_delete_comment mangle FORWARD "mex:tcpmss" || return 1
  mex_iptables_remove_jump nat PREROUTING MEX_PREROUTING || return 1
  mex_iptables_remove_jump nat POSTROUTING MEX_POSTROUTING || return 1
  mex_iptables_remove_jump filter FORWARD MEX_FORWARD || return 1
  mex_iptables_empty_own_chain nat MEX_PREROUTING || return 1
  mex_iptables_empty_own_chain nat MEX_POSTROUTING || return 1
  mex_iptables_empty_own_chain filter MEX_FORWARD || return 1
}

mex_iptables_has_comment() {
  local table="$1" chain="$2" comment="$3"
  local out
  out="$(mex_iptables_list "$table" "$chain")"
  [[ "$out" == *"/* ${comment} */"* ]]
}
