#!/usr/bin/env bash
# Правила проброса Multi-Exit Relay.
#
# Собственные цепочки:
#   nat/MEX_PREROUTING, nat/MEX_POSTROUTING, filter/MEX_FORWARD
# Переход из системных цепочек ставится один раз, в позицию 1.
# На каждый Exit — отдельные DNAT, FORWARD и MASQUERADE с комментарием mex:<id>.
# Глобальная MASQUERADE не используется. UDP нет. SNI не меняется.
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

mex_iptables_validate_endpoint() {
  local id="$1" ip="$2" rp1="$3" rp2="$4" ep1="$5" ep2="$6"
  mex_valid_exit_id "$id" || return 1
  mex_valid_ipv4 "$ip" || return 1
  mex_valid_port "$rp1" || return 1
  mex_valid_port "$rp2" || return 1
  [[ "$ep1" == "443" && "$ep2" == "8443" ]] || return 1
  (( rp1 != rp2 )) || return 1
  return 0
}

mex_iptables_apply_exit() {
  local id="$1" ip="$2" rp1="$3" rp2="$4" ep1="$5" ep2="$6"
  local c="mex:${id}"
  if ! mex_iptables_validate_endpoint "$id" "$ip" "$rp1" "$rp2" "$ep1" "$ep2"; then
    mex_fail "Внутренние параметры Exit ${id} не прошли проверку. Правила не изменены." || true
    return 1
  fi
  mex_iptables_ensure_base || return 1
  mex_iptables_ensure_rule nat MEX_PREROUTING \
    -p tcp --dport "$rp1" -m comment --comment "$c" -j DNAT --to-destination "${ip}:${ep1}" || return 1
  mex_iptables_ensure_rule nat MEX_PREROUTING \
    -p tcp --dport "$rp2" -m comment --comment "$c" -j DNAT --to-destination "${ip}:${ep2}" || return 1
  mex_iptables_ensure_rule nat MEX_POSTROUTING \
    -p tcp -d "$ip" --dport "$ep1" -m comment --comment "$c" -j MASQUERADE || return 1
  mex_iptables_ensure_rule nat MEX_POSTROUTING \
    -p tcp -d "$ip" --dport "$ep2" -m comment --comment "$c" -j MASQUERADE || return 1
  mex_iptables_ensure_rule filter MEX_FORWARD \
    -p tcp -d "$ip" --dport "$ep1" -m conntrack --ctstate NEW -m comment --comment "$c" -j ACCEPT || return 1
  mex_iptables_ensure_rule filter MEX_FORWARD \
    -p tcp -d "$ip" --dport "$ep2" -m conntrack --ctstate NEW -m comment --comment "$c" -j ACCEPT || return 1
  mex_iptables_ensure_rule filter MEX_FORWARD \
    -p tcp -d "$ip" --dport "$ep1" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT || return 1
  mex_iptables_ensure_rule filter MEX_FORWARD \
    -p tcp -s "$ip" --sport "$ep1" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT || return 1
  mex_iptables_ensure_rule filter MEX_FORWARD \
    -p tcp -d "$ip" --dport "$ep2" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT || return 1
  mex_iptables_ensure_rule filter MEX_FORWARD \
    -p tcp -s "$ip" --sport "$ep2" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$c" -j ACCEPT || return 1
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
  local id="$1"
  local ip rp1 rp2 ep1 ep2
  IFS=$'\t' read -r ip rp1 rp2 ep1 ep2 < <(
    jq -r --arg id "$id" '
      .exits[] | select(.id == $id)
      | [.ip, .relay_port_443, .relay_port_8443, .exit_port_443, .exit_port_8443]
      | @tsv
    ' "$MEX_CONFIG_FILE"
  )
  if [[ -z "${ip:-}" ]]; then
    mex_fail "Exit ${id} не найден в конфигурации." || true
    return 1
  fi
  mex_iptables_apply_exit "$id" "$ip" "$rp1" "$rp2" "$ep1" "$ep2"
}

mex_iptables_apply_config() {
  local id
  if [[ ! -f "$MEX_CONFIG_FILE" ]]; then
    mex_fail "Нет файла конфигурации ${MEX_CONFIG_FILE}." || true
    return 1
  fi
  if ! mex_config_validate_file "$MEX_CONFIG_FILE"; then
    mex_fail "Файл ${MEX_CONFIG_FILE} не прошёл проверку схемы." || true
    return 1
  fi
  mex_iptables_ensure_base || return 1
  mex_iptables_drop_orphans || return 1
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    mex_iptables_apply_exit_from_config "$id" || return 1
  done < <(jq -r '.exits[].id' "$MEX_CONFIG_FILE")
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
