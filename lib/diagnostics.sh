#!/usr/bin/env bash
# Проверка правил проброса и доступности TCP-портов Exit.
# TCP-проверка не является проверкой REALITY, VLESS, Hysteria2 или VPN.
# UDP-доступность не проверяется: в отчёте reachability = not_checkable.

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
# shellcheck source=resolve.sh
source "$(dirname "${BASH_SOURCE[0]}")/resolve.sh"

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

mex_diag_netfilter_token() {
  local enabled
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    printf '%s\n' "dry_run"
    return 0
  fi
  if ! mex_have netfilter-persistent; then
    printf '%s\n' "not_installed"
    return 0
  fi
  if ! mex_have systemctl; then
    printf '%s\n' "unknown"
    return 0
  fi
  enabled="$(systemctl is-enabled netfilter-persistent 2>/dev/null || true)"
  case "$enabled" in
    enabled|disabled|static|indirect|generated) printf '%s\n' "$enabled" ;;
    *) printf '%s\n' "unknown" ;;
  esac
}

mex_diag_ufw_active() {
  if mex_have ufw && timeout 3 ufw status 2>/dev/null | grep -q "Status: active"; then
    printf '%s\n' "true"
  else
    printf '%s\n' "false"
  fi
}

mex_report_error() {
  local command="$1"
  local err="$2"
  local message="$3"
  jq -n \
    --arg command "$command" \
    --arg error "$err" \
    --arg message "$message" \
    --arg version "$MEX_VERSION" \
    --arg config_file "${MEX_CONFIG_FILE:-}" \
    '{
      ok: false,
      command: $command,
      error: $error,
      message: $message,
      version: $version,
      config_file: $config_file,
      problems: [{code: $error, message: $message}],
      warnings: [],
      exits: []
    }'
}

# Собирает отчёт check/status. Печатает один JSON-документ и возвращает 0, 2 или 4.
mex_collect_report() {
  local command="$1"
  local norm rc=0
  local problems='[]' warnings='[]' exits='[]'
  local ip_forward ip_forward_json policy nf ufw
  local chain_pre=false chain_post=false chain_fwd=false
  local jump_pre=false jump_post=false jump_fwd=false
  local tcpmss=false has_tcp=false has_forward=false
  local pub iface config_version
  if [[ ! -f "${MEX_CONFIG_FILE:-}" ]]; then
    mex_report_error "$command" config_missing "Конфигурация отсутствует: ${MEX_CONFIG_FILE}"
    return 2
  fi
  if ! mex_config_validate_file "$MEX_CONFIG_FILE"; then
    mex_report_error "$command" config_invalid "Файл ${MEX_CONFIG_FILE} не прошёл проверку схемы."
    return 2
  fi
  norm="$(mex_config_normalize_json "$MEX_CONFIG_FILE")"
  config_version="$(jq -r '.version' <<<"$norm")"
  pub="$(jq -r '.public_ip // empty' <<<"$norm")"
  iface="$(jq -r '.egress_interface // empty' <<<"$norm")"
  ip_forward="$(mex_read_ip_forward)"
  if [[ "$ip_forward" == "1" ]]; then
    ip_forward_json="1"
  elif [[ "$ip_forward" =~ ^[0-9]+$ ]]; then
    ip_forward_json="$ip_forward"
  else
    ip_forward_json="null"
  fi
  policy="$(mex_diag_forward_policy)"
  nf="$(mex_diag_netfilter_token)"
  ufw="$(mex_diag_ufw_active)"
  if mex_iptables_chain_exists nat MEX_PREROUTING; then chain_pre=true; fi
  if mex_iptables_chain_exists nat MEX_POSTROUTING; then chain_post=true; fi
  if mex_iptables_chain_exists filter MEX_FORWARD; then chain_fwd=true; fi
  if mex_iptables -t nat -C PREROUTING -j MEX_PREROUTING >/dev/null 2>&1; then jump_pre=true; fi
  if mex_iptables -t nat -C POSTROUTING -j MEX_POSTROUTING >/dev/null 2>&1; then jump_post=true; fi
  if mex_iptables -C FORWARD -j MEX_FORWARD >/dev/null 2>&1; then jump_fwd=true; fi
  if mex_iptables_has_comment mangle FORWARD "mex:tcpmss"; then tcpmss=true; fi

  local exit_json id name host rip stale_flag forwards_json exit_ok exit_rip=""
  while IFS= read -r exit_json; do
    [[ -n "$exit_json" ]] || continue
    exit_rip=""
    id="$(jq -r '.id' <<<"$exit_json")"
    name="$(jq -r '.name' <<<"$exit_json")"
    host="$(jq -r '.host' <<<"$exit_json")"
    stale_flag="false"
    if [[ -f "${MEX_STATE_FILE:-}" ]]; then
      stale_flag="$(jq -r --arg id "$id" '.resolved[$id].stale // false' "$MEX_STATE_FILE" 2>/dev/null || printf 'false')"
    fi
    forwards_json='[]'
    exit_ok=true
    local fw proto listen target dnat masq fwd rule_present
    local reachability reachable_json packets_json bytes_json
    while IFS= read -r fw; do
      [[ -n "$fw" ]] || continue
      has_forward=true
      proto="$(jq -r '.proto' <<<"$fw")"
      listen="$(jq -r '.listen' <<<"$fw")"
      target="$(jq -r '.target' <<<"$fw")"
      [[ "$proto" == "tcp" ]] && has_tcp=true
      rip=""
      if rip="$(mex_dnat_destination_ip "$id" "$proto" "$listen" "$target")"; then
        :
      elif mex_valid_ipv4 "$host"; then
        rip="$host"
      elif [[ -f "${MEX_STATE_FILE:-}" ]]; then
        rip="$(jq -r --arg id "$id" '.resolved[$id].selected // empty' "$MEX_STATE_FILE" 2>/dev/null || true)"
      fi
      dnat=0 masq=0 fwd=0
      if [[ -n "$rip" ]] && mex_valid_ipv4 "$rip"; then
        read -r dnat masq fwd < <(mex_iptables_forward_flags "$id" "$rip" "$proto" "$listen" "$target")
      fi
      if [[ "$dnat" == "1" && "$masq" == "1" && "$fwd" == "1" ]]; then
        rule_present=true
      else
        rule_present=false
        exit_ok=false
        rc=4
        problems="$(jq -nc \
          --argjson problems "$problems" \
          --arg id "$id" \
          --arg proto "$proto" \
          --argjson listen "$listen" \
          --argjson target "$target" \
          '$problems + [{code:"rule_missing", id:$id, proto:$proto, listen:$listen, target:$target}]')"
      fi
      packets_json="null"
      bytes_json="null"
      if [[ -n "$rip" ]]; then
        local pkts bytes
        if read -r pkts bytes < <(mex_dnat_counters "$id" "$proto" "$listen" "$rip" "$target"); then
          packets_json="$pkts"
          bytes_json="$bytes"
        fi
      fi
      if [[ "$proto" == "udp" ]]; then
        reachability="not_checkable"
        reachable_json="null"
      elif [[ -z "$rip" ]] || ! mex_valid_ipv4 "$rip"; then
        reachability="unreachable"
        reachable_json="false"
        exit_ok=false
        rc=4
        problems="$(jq -nc \
          --argjson problems "$problems" \
          --arg id "$id" \
          --arg host "$host" \
          '$problems + [{code:"resolve_failed", id:$id, host:$host}]')"
      elif mex_tcp_probe "$rip" "$target" 3; then
        reachability="ok"
        reachable_json="true"
      else
        reachability="unreachable"
        reachable_json="false"
        exit_ok=false
        rc=4
        problems="$(jq -nc \
          --argjson problems "$problems" \
          --arg id "$id" \
          --arg proto "$proto" \
          --argjson listen "$listen" \
          --argjson target "$target" \
          '$problems + [{code:"tcp_unreachable", id:$id, proto:$proto, listen:$listen, target:$target}]')"
      fi
      local one
      one="$(jq -n \
        --arg proto "$proto" \
        --argjson listen "$listen" \
        --argjson target "$target" \
        --argjson rule_present "$rule_present" \
        --argjson dnat "$([[ "$dnat" == 1 ]] && printf true || printf false)" \
        --argjson forward "$([[ "$fwd" == 1 ]] && printf true || printf false)" \
        --argjson masquerade "$([[ "$masq" == 1 ]] && printf true || printf false)" \
        --argjson reachable "$reachable_json" \
        --arg reachability "$reachability" \
        --argjson packets "$packets_json" \
        --argjson bytes "$bytes_json" \
        '{
          proto: $proto,
          listen: $listen,
          target: $target,
          rule_present: $rule_present,
          dnat: $dnat,
          forward: $forward,
          masquerade: $masquerade,
          reachable: $reachable,
          reachability: $reachability,
          packets: $packets,
          bytes: $bytes
        }')"
      forwards_json="$(jq -nc --argjson a "$forwards_json" --argjson b "$one" '$a + [$b]')"
      # resolved_ip отчёта — адрес, по которому проверяли этот проброс.
      # Для нескольких пробросов он один и тот же; берём последний непустой.
      if [[ -n "$rip" ]]; then
        exit_rip="$rip"
      fi
    done < <(jq -c '.forwards[]?' <<<"$exit_json")
    if [[ "${stale_flag}" == "true" ]]; then
      warnings="$(jq -nc \
        --argjson warnings "$warnings" \
        --arg id "$id" \
        --arg host "$host" \
        --arg ip "${exit_rip:-}" \
        '$warnings + [{code:"resolve_stale", id:$id, host:$host, resolved_ip:(if $ip=="" then null else $ip end)}]')"
    fi
    local exit_obj exit_rip_json
    if [[ -n "${exit_rip:-}" ]]; then
      exit_rip_json="$(jq -n --arg ip "$exit_rip" '$ip')"
    else
      exit_rip_json="null"
    fi
    exit_obj="$(jq -n \
      --arg id "$id" \
      --arg name "$name" \
      --arg host "$host" \
      --argjson resolved_ip "$exit_rip_json" \
      --argjson resolve_stale "$([[ "$stale_flag" == true ]] && printf true || printf false)" \
      --argjson ok "$([[ "$exit_ok" == true ]] && printf true || printf false)" \
      --argjson forwards "$forwards_json" \
      '{
        id: $id,
        name: $name,
        host: $host,
        resolved_ip: $resolved_ip,
        resolve_stale: $resolve_stale,
        ok: $ok,
        forwards: $forwards
      }')"
    exits="$(jq -nc --argjson a "$exits" --argjson b "$exit_obj" '$a + [$b]')"
    exit_rip=""
  done < <(jq -c '.exits[]?' <<<"$norm")

  if [[ "$has_forward" == true ]]; then
    if [[ "$ip_forward" != "1" ]]; then
      rc=4
      problems="$(jq -nc --argjson problems "$problems" '$problems + [{code:"ip_forward_disabled"}]')"
    fi
    if [[ "$chain_pre" != true ]]; then
      rc=4
      problems="$(jq -nc --argjson problems "$problems" '$problems + [{code:"chain_missing", chain:"MEX_PREROUTING"}]')"
    fi
    if [[ "$chain_post" != true ]]; then
      rc=4
      problems="$(jq -nc --argjson problems "$problems" '$problems + [{code:"chain_missing", chain:"MEX_POSTROUTING"}]')"
    fi
    if [[ "$chain_fwd" != true ]]; then
      rc=4
      problems="$(jq -nc --argjson problems "$problems" '$problems + [{code:"chain_missing", chain:"MEX_FORWARD"}]')"
    fi
    if [[ "$jump_pre" != true ]]; then
      rc=4
      problems="$(jq -nc --argjson problems "$problems" '$problems + [{code:"jump_missing", chain:"PREROUTING"}]')"
    fi
    if [[ "$jump_post" != true ]]; then
      rc=4
      problems="$(jq -nc --argjson problems "$problems" '$problems + [{code:"jump_missing", chain:"POSTROUTING"}]')"
    fi
    if [[ "$jump_fwd" != true ]]; then
      rc=4
      problems="$(jq -nc --argjson problems "$problems" '$problems + [{code:"jump_missing", chain:"FORWARD"}]')"
    fi
    if [[ "$has_tcp" == true && "$tcpmss" != true ]]; then
      warnings="$(jq -nc --argjson warnings "$warnings" '$warnings + [{code:"tcpmss_missing"}]')"
    fi
  fi

  local ok=true
  if (( rc != 0 )); then
    ok=false
  fi
  jq -n \
    --argjson ok "$ok" \
    --arg command "$command" \
    --arg version "$MEX_VERSION" \
    --argjson config_version "$config_version" \
    --arg config_file "$MEX_CONFIG_FILE" \
    --arg pub "$pub" \
    --arg iface "$iface" \
    --argjson ip_forward "$ip_forward_json" \
    --argjson tcpmss "$tcpmss" \
    --argjson chain_pre "$chain_pre" \
    --argjson chain_post "$chain_post" \
    --argjson chain_fwd "$chain_fwd" \
    --argjson jump_pre "$jump_pre" \
    --argjson jump_post "$jump_post" \
    --argjson jump_fwd "$jump_fwd" \
    --arg policy "$policy" \
    --arg nf "$nf" \
    --argjson ufw "$ufw" \
    --argjson problems "$problems" \
    --argjson warnings "$warnings" \
    --argjson exits "$exits" \
    '{
      ok: $ok,
      command: $command,
      version: $version,
      config_version: $config_version,
      config_file: $config_file,
      public_ip: (if $pub == "" then null else $pub end),
      egress_interface: (if $iface == "" then null else $iface end),
      ip_forward: $ip_forward,
      tcpmss: $tcpmss,
      chains: {
        MEX_PREROUTING: $chain_pre,
        MEX_POSTROUTING: $chain_post,
        MEX_FORWARD: $chain_fwd
      },
      jumps: {
        PREROUTING: $jump_pre,
        POSTROUTING: $jump_post,
        FORWARD: $jump_fwd
      },
      forward_policy: $policy,
      netfilter_persistent: $nf,
      ufw_active: $ufw,
      problems: $problems,
      warnings: $warnings,
      exits: $exits
    }'
  return "$rc"
}

mex_render_human() {
  local json="$1"
  local err
  err="$(jq -r '.error // empty' <<<"$json")"
  if [[ -n "$err" ]]; then
    jq -r '.message // .error' <<<"$json"
    return 0
  fi
  printf '%s\n' "Проверка Multi-Exit Relay"
  printf '%s\n' "Это проверка правил проброса и доступности TCP-портов. Это не проверка REALITY, VLESS, Hysteria2 или VPN."
  printf '\n'
  printf 'ip_forward: %s\n' "$(jq -r '.ip_forward // "unknown"' <<<"$json")"
  if jq -e '.tcpmss == true' <<<"$json" >/dev/null; then
    printf '%s\n' "TCPMSS: присутствует"
  else
    printf '%s\n' "TCPMSS: отсутствует"
  fi
  printf 'netfilter-persistent: %s\n' "$(jq -r '.netfilter_persistent' <<<"$json")"
  printf 'политика FORWARD: %s\n' "$(jq -r '.forward_policy' <<<"$json")"
  jq -r '.chains | to_entries[] | "цепочка \(.key): \(if .value then "да" else "нет" end)"' <<<"$json"
  jq -r '.jumps | to_entries[] | "переход \(.key): \(if .value then "да" else "нет" end)"' <<<"$json"
  if jq -e '.ufw_active == true' <<<"$json" >/dev/null; then
    printf '%s\n' "UFW: активен (не отключается установщиком)"
  else
    printf '%s\n' "UFW: не активен или не установлен"
  fi
  printf '\n'
  local table
  table="$(mktemp)"
  {
    printf 'СТРАНА\tHOST\tПРОТОКОЛ\tПОРТ RELAY\tПОРТ EXIT\tПРАВИЛО\tДОСТУПНОСТЬ\n'
    jq -r '
      .exits[]? | .name as $n | .host as $h | .forwards[]? |
      [
        $n,
        $h,
        .proto,
        (.listen|tostring),
        (.target|tostring),
        (if .rule_present then "да" else "нет" end),
        (if .reachability == "ok" then "да"
         elif .reachability == "not_checkable" then "udp не проверяется"
         else "нет" end)
      ] | @tsv
    ' <<<"$json"
  } >"$table"
  if [[ "$(jq -r '[.exits[]?.forwards[]?] | length' <<<"$json")" == "0" ]]; then
    printf '%s\n' "Список пробросов пуст."
  elif command -v column >/dev/null 2>&1; then
    column -t -s $'\t' <"$table"
  else
    cat "$table"
  fi
  rm -f "$table"
  printf '\n%s\n' "Колонка доступности для TCP — только открытие TCP-порта, не проверка VPN. Для UDP проверка соединения не выполняется."
}

mex_diag_check() {
  local json rc=0
  json="$(mex_collect_report check)" || rc=$?
  if [[ "${MEX_JSON:-0}" == "1" ]]; then
    printf '%s\n' "$json"
  else
    mex_render_human "$json"
  fi
  return "$rc"
}

mex_diag_connections() {
  local json rc=0
  printf '%s\n' "Проверка соединений"
  printf '%s\n' "Проверяется только доступность TCP-порта. Это не проверка REALITY, VLESS, Hysteria2 или VPN. UDP не проверяется."
  if [[ ! -f "${MEX_CONFIG_FILE:-}" ]]; then
    mex_info "Конфигурация отсутствует."
    return 0
  fi
  json="$(mex_collect_report check)" || rc=$?
  local table
  table="$(mktemp)"
  {
    printf 'СТРАНА\tHOST\tПРОТОКОЛ\tПОРТ EXIT\tДОСТУПНОСТЬ\n'
    jq -r '
      .exits[]? | .name as $n | .host as $h | .forwards[]? |
      [
        $n, $h, .proto, (.target|tostring),
        (if .reachability == "ok" then "доступен"
         elif .reachability == "not_checkable" then "не проверяется"
         else "недоступен" end)
      ] | @tsv
    ' <<<"$json"
  } >"$table"
  if command -v column >/dev/null 2>&1; then
    column -t -s $'\t' <"$table"
  else
    cat "$table"
  fi
  rm -f "$table"
  return "$rc"
}

mex_diag_nat() {
  local json rc=0
  printf '%s\n' "Проверка NAT и файрвола"
  if [[ ! -f "${MEX_CONFIG_FILE:-}" ]]; then
    mex_info "Конфигурация отсутствует."
    return 2
  fi
  json="$(mex_collect_report check)" || rc=$?
  mex_render_human "$json"
  return "$rc"
}
