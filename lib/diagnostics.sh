#!/usr/bin/env bash
# Проверка TCP-портов Exit и наличия правил проброса.
# TCP-проверка не является проверкой REALITY, VLESS или VPN.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_DIAG_LOADED:-}" ]] && return 0
MEX_DIAG_LOADED=1

# shellcheck source=iptables.sh
source "$(dirname "${BASH_SOURCE[0]}")/iptables.sh"
# shellcheck source=ports.sh
source "$(dirname "${BASH_SOURCE[0]}")/ports.sh"

mex_read_ip_forward() {
  local value
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    if [[ -f "${MEX_SYSCTL_FILE:-}" ]] && grep -q '^net.ipv4.ip_forward=1' "$MEX_SYSCTL_FILE"; then
      printf '%s\n' "1"
      return 0
    fi
    printf '%s\n' "0"
    return 0
  fi
  if value="$("${MEX_SYSCTL_BIN}" -n net.ipv4.ip_forward 2>/dev/null)"; then
    printf '%s\n' "$value"
    return 0
  fi
  if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
    tr -d '[:space:]' </proc/sys/net/ipv4/ip_forward
    return 0
  fi
  printf '%s\n' "unknown"
}

mex_diag_forward_policy() {
  local line policy=""
  while IFS= read -r line; do
    if [[ "$line" == "-P FORWARD "* ]]; then
      policy="${line#-P FORWARD }"
      break
    fi
  done < <(mex_iptables -S FORWARD 2>/dev/null || true)
  printf '%s\n' "${policy:-неизвестно}"
}

mex_diag_netfilter_state() {
  local enabled extra
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    printf '%s\n' "dry-run (ядро не изменялось)"
    return 0
  fi
  if ! mex_have netfilter-persistent; then
    printf '%s\n' "не установлен"
    return 0
  fi
  enabled="состояние службы неизвестно"
  if mex_have systemctl; then
    enabled="$(systemctl is-enabled netfilter-persistent 2>/dev/null || true)"
    [[ -n "$enabled" ]] || enabled="не включён"
  fi
  extra="в rules.v4 нет цепочек MEX"
  if [[ -f /etc/iptables/rules.v4 ]] && grep -q 'MEX_PREROUTING' /etc/iptables/rules.v4; then
    extra="rules.v4 содержит MEX_PREROUTING"
  fi
  printf 'установлен (%s), %s\n' "$enabled" "$extra"
}

mex_diag_yes_no() {
  if [[ "$1" == "1" ]]; then
    printf '%s' "да"
  else
    printf '%s' "нет"
  fi
}

mex_diag_listener_conflict() {
  local port="$1"
  mex_ports_reset
  mex_ports_scan_listeners
  mex_ports_is_occupied "$port"
}

mex_diag_dnat_conflict() {
  local port="$1"
  local id="$2"
  local line dport
  while IFS= read -r line; do
    [[ "$line" == *"-j DNAT"* || "$line" == *"-j REDIRECT"* ]] || continue
    [[ "$line" =~ --dport[[:space:]]+([0-9]+) ]] || continue
    dport="${BASH_REMATCH[1]}"
    [[ "$dport" == "$port" ]] || continue
    if [[ "$line" == *"mex:${id}"* ]]; then
      continue
    fi
    return 0
  done < <(mex_iptables -t nat -S 2>/dev/null || true)
  return 1
}

mex_diag_port_conflict_text() {
  local id="$1" p1="$2" p2="$3"
  local -a reasons=()
  local n
  n="$(jq -r --argjson p1 "$p1" --argjson p2 "$p2" '
    [.exits[] | select(
      .relay_port_443 == $p1 or .relay_port_8443 == $p1 or
      .relay_port_443 == $p2 or .relay_port_8443 == $p2
    )] | length
  ' "$MEX_CONFIG_FILE")"
  if (( n > 2 )); then
    reasons+=("порты повторяются у нескольких Exit")
  elif (( n > 1 )); then
    local owners
    owners="$(jq -r --argjson p1 "$p1" --argjson p2 "$p2" '
      [.exits[] | select(
        .relay_port_443 == $p1 or .relay_port_8443 == $p1 or
        .relay_port_443 == $p2 or .relay_port_8443 == $p2
      ) | .id] | unique | length
    ' "$MEX_CONFIG_FILE")"
    if (( owners > 1 )); then
      reasons+=("порты совпадают с другим Exit")
    fi
  fi
  if mex_diag_listener_conflict "$p1"; then
    reasons+=("порт ${p1} занят локальным слушателем")
  fi
  if mex_diag_listener_conflict "$p2"; then
    reasons+=("порт ${p2} занят локальным слушателем")
  fi
  if mex_diag_dnat_conflict "$p1" "$id"; then
    reasons+=("чужой DNAT занимает порт ${p1}")
  fi
  if mex_diag_dnat_conflict "$p2" "$id"; then
    reasons+=("чужой DNAT занимает порт ${p2}")
  fi
  if ((${#reasons[@]} == 0)); then
    printf '%s' "нет"
    return 1
  fi
  local joined="" part
  for part in "${reasons[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+="; "
    fi
    joined+="$part"
  done
  printf 'да: %s' "$joined"
  return 0
}

mex_diag_print_header() {
  local forward_value chains
  printf '%s\n' "Проверка Multi-Exit Relay"
  printf '%s\n' "Это проверка правил проброса и доступности TCP-портов. Это не проверка REALITY, VLESS или VPN."
  printf '\n'
  forward_value="$(mex_read_ip_forward)"
  printf 'ip_forward: %s\n' "$forward_value"
  if mex_iptables_has_comment mangle FORWARD "mex:tcpmss"; then
    printf '%s\n' "TCPMSS: присутствует"
  else
    printf '%s\n' "TCPMSS: отсутствует"
    MEX_CHECK_PROBLEMS=1
  fi
  printf 'netfilter-persistent: %s\n' "$(mex_diag_netfilter_state)"
  printf 'политика FORWARD: %s\n' "$(mex_diag_forward_policy)"
  for chains in "nat MEX_PREROUTING" "nat MEX_POSTROUTING" "filter MEX_FORWARD"; do
    local table chain present
    read -r table chain <<<"$chains"
    if mex_iptables_chain_exists "$table" "$chain"; then
      present="да"
    else
      present="нет"
      MEX_CHECK_PROBLEMS=1
    fi
    printf 'цепочка %s: %s\n' "$chain" "$present"
  done
  local jump_ok
  jump_ok=1
  mex_iptables -t nat -C PREROUTING -j MEX_PREROUTING >/dev/null 2>&1 || jump_ok=0
  printf 'переход PREROUTING -> MEX_PREROUTING: %s\n' "$(mex_diag_yes_no "$jump_ok")"
  [[ "$jump_ok" == "1" ]] || MEX_CHECK_PROBLEMS=1
  jump_ok=1
  mex_iptables -t nat -C POSTROUTING -j MEX_POSTROUTING >/dev/null 2>&1 || jump_ok=0
  printf 'переход POSTROUTING -> MEX_POSTROUTING: %s\n' "$(mex_diag_yes_no "$jump_ok")"
  [[ "$jump_ok" == "1" ]] || MEX_CHECK_PROBLEMS=1
  jump_ok=1
  mex_iptables -C FORWARD -j MEX_FORWARD >/dev/null 2>&1 || jump_ok=0
  printf 'переход FORWARD -> MEX_FORWARD: %s\n' "$(mex_diag_yes_no "$jump_ok")"
  [[ "$jump_ok" == "1" ]] || MEX_CHECK_PROBLEMS=1
  if [[ "$forward_value" != "1" ]]; then
    MEX_CHECK_PROBLEMS=1
  fi
  if mex_have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    printf '%s\n' "UFW: активен (не отключается установщиком)"
  else
    printf '%s\n' "UFW: не активен или не установлен"
  fi
}

mex_diag_render_table() {
  local file="$1"
  if command -v column >/dev/null 2>&1; then
    column -t -s $'\t' <"$file"
  else
    cat "$file"
  fi
}

mex_diag_check() {
  local id name ip p1 p2 tcp443 tcp8443 dnat fwd masq conflict
  local table
  MEX_CHECK_PROBLEMS=0
  mex_diag_print_header
  printf '\n'
  if [[ ! -f "${MEX_CONFIG_FILE:-}" ]]; then
    printf '%s\n' "Конфигурация отсутствует."
    return 1
  fi
  if ! jq -e '.exits | length > 0' "$MEX_CONFIG_FILE" >/dev/null 2>&1; then
    printf '%s\n' "Список Exit пуст."
    return "$MEX_CHECK_PROBLEMS"
  fi
  table="$(mktemp)"
  {
    printf 'СТРАНА\tIP EXIT\tTCP/443\tTCP/8443\tDNAT\tFORWARD\tMASQUERADE\tКОНФЛИКТ ПОРТОВ\n'
    while IFS=$'\t' read -r id name ip p1 p2; do
      [[ -n "$id" ]] || continue
      if mex_tcp_probe "$ip" 443 5; then tcp443="да"; else tcp443="нет"; MEX_CHECK_PROBLEMS=1; fi
      if mex_tcp_probe "$ip" 8443 5; then tcp8443="да"; else tcp8443="нет"; MEX_CHECK_PROBLEMS=1; fi
      if mex_iptables_has_comment nat MEX_PREROUTING "mex:${id}"; then dnat="да"; else dnat="нет"; MEX_CHECK_PROBLEMS=1; fi
      if mex_iptables_has_comment filter MEX_FORWARD "mex:${id}"; then fwd="да"; else fwd="нет"; MEX_CHECK_PROBLEMS=1; fi
      if mex_iptables_has_comment nat MEX_POSTROUTING "mex:${id}"; then masq="да"; else masq="нет"; MEX_CHECK_PROBLEMS=1; fi
      if conflict="$(mex_diag_port_conflict_text "$id" "$p1" "$p2")"; then
        MEX_CHECK_PROBLEMS=1
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$ip" "$tcp443" "$tcp8443" "$dnat" "$fwd" "$masq" "$conflict"
    done < <(jq -r '.exits[] | [.id, .name, .ip, (.relay_port_443|tostring), (.relay_port_8443|tostring)] | @tsv' "$MEX_CONFIG_FILE")
  } >"$table"
  mex_diag_render_table "$table"
  rm -f "$table"
  printf '\n%s\n' "Колонки TCP/443 и TCP/8443 — только проверка открытия TCP-порта, не проверка REALITY или VPN."
  return "$MEX_CHECK_PROBLEMS"
}

mex_diag_connections() {
  local id name ip ok443 ok8443
  printf '%s\n' "Проверка соединений"
  printf '%s\n' "Проверяется только доступность TCP-порта. Это не проверка REALITY, VLESS или VPN."
  if [[ ! -f "${MEX_CONFIG_FILE:-}" ]] || ! jq -e '.exits | length > 0' "$MEX_CONFIG_FILE" >/dev/null 2>&1; then
    mex_info "Список Exit пуст."
    return 0
  fi
  local table
  table="$(mktemp)"
  {
    printf 'СТРАНА\tIP EXIT\tTCP/443\tTCP/8443\n'
    while IFS=$'\t' read -r id name ip; do
      [[ -n "$id" ]] || continue
      if mex_tcp_probe "$ip" 443 5; then ok443="доступен"; else ok443="недоступен"; fi
      if mex_tcp_probe "$ip" 8443 5; then ok8443="доступен"; else ok8443="недоступен"; fi
      printf '%s\t%s\t%s\t%s\n' "$name" "$ip" "$ok443" "$ok8443"
    done < <(jq -r '.exits[] | [.id, .name, .ip] | @tsv' "$MEX_CONFIG_FILE")
  } >"$table"
  mex_diag_render_table "$table"
  rm -f "$table"
}

mex_diag_nat() {
  MEX_CHECK_PROBLEMS=0
  printf '%s\n' "Проверка NAT и файрвола"
  mex_diag_print_header
  if [[ -f "${MEX_CONFIG_FILE:-}" ]] && jq -e '.exits | length > 0' "$MEX_CONFIG_FILE" >/dev/null 2>&1; then
    printf '\n'
    local id name ip p1 p2 dnat fwd masq conflict table
    table="$(mktemp)"
    {
      printf 'СТРАНА\tIP EXIT\tDNAT\tFORWARD\tMASQUERADE\tКОНФЛИКТ ПОРТОВ\n'
      while IFS=$'\t' read -r id name ip p1 p2; do
        [[ -n "$id" ]] || continue
        if mex_iptables_has_comment nat MEX_PREROUTING "mex:${id}"; then dnat="да"; else dnat="нет"; MEX_CHECK_PROBLEMS=1; fi
        if mex_iptables_has_comment filter MEX_FORWARD "mex:${id}"; then fwd="да"; else fwd="нет"; MEX_CHECK_PROBLEMS=1; fi
        if mex_iptables_has_comment nat MEX_POSTROUTING "mex:${id}"; then masq="да"; else masq="нет"; MEX_CHECK_PROBLEMS=1; fi
        if conflict="$(mex_diag_port_conflict_text "$id" "$p1" "$p2")"; then
          MEX_CHECK_PROBLEMS=1
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$ip" "$dnat" "$fwd" "$masq" "$conflict"
      done < <(jq -r '.exits[] | [.id, .name, .ip, (.relay_port_443|tostring), (.relay_port_8443|tostring)] | @tsv' "$MEX_CONFIG_FILE")
    } >"$table"
    mex_diag_render_table "$table"
    rm -f "$table"
  fi
  return "$MEX_CHECK_PROBLEMS"
}
