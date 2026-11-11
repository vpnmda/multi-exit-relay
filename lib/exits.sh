#!/usr/bin/env bash
# Добавление, удаление и смена IP Exit, конфигурация, sysctl, systemd и CLI.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_EXITS_LOADED:-}" ]] && return 0
MEX_EXITS_LOADED=1

# shellcheck source=ports.sh
source "$(dirname "${BASH_SOURCE[0]}")/ports.sh"
# shellcheck source=backup.sh
source "$(dirname "${BASH_SOURCE[0]}")/backup.sh"

mex_config_ensure() {
  local now pub iface
  mex_ensure_dirs
  if [[ -f "$MEX_CONFIG_FILE" ]]; then
    if ! mex_config_validate_file "$MEX_CONFIG_FILE"; then
      mex_fail "Файл ${MEX_CONFIG_FILE} повреждён или имеет неподдерживаемую схему." || true
      return 1
    fi
    if [[ "$(jq -r '.version // empty' "$MEX_CONFIG_FILE")" == "1" ]]; then
      if ! mex_config_migrate_inplace "$MEX_CONFIG_FILE"; then
        mex_fail "Не удалось перевести ${MEX_CONFIG_FILE} со схемы v1 на v2." || true
        return 1
      fi
    fi
    return 0
  fi
  now="$(mex_timestamp)"
  pub="${MEX_PUBLIC_IP:-}"
  iface="${MEX_EGRESS_IFACE:-}"
  jq -n \
    --arg pub "$pub" \
    --arg iface "$iface" \
    --arg now "$now" \
    '{
      version: 2,
      public_ip: $pub,
      egress_interface: $iface,
      created_at: $now,
      next_seq: 1,
      exits: []
    }' | mex_atomic_write "$MEX_CONFIG_FILE"
}

mex_config_set_host() {
  local pub="$1" iface="$2"
  local tmp
  mex_config_ensure || return 1
  tmp="$(mktemp)"
  jq --arg pub "$pub" --arg iface "$iface" '
    .public_ip = $pub | .egress_interface = $iface
  ' "$MEX_CONFIG_FILE" >"$tmp"
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$MEX_CONFIG_FILE"
}

mex_tcp_probe() {
  local ip="$1"
  local port="$2"
  local timeout_s="${3:-5}"
  local result
  if [[ -n "${MEX_TCP_STUB_FILE:-}" ]]; then
    if [[ ! -f "$MEX_TCP_STUB_FILE" ]]; then
      return 1
    fi
    result="$(awk -v exact="${ip}:${port}" -v wild="${ip}:*" '
      $1 == exact { exact_res = $2; has_exact = 1 }
      $1 == wild && !has_wild { wild_res = $2; has_wild = 1 }
      END {
        if (has_exact) print exact_res
        else if (has_wild) print wild_res
        else print "fail"
      }
    ' "$MEX_TCP_STUB_FILE")"
    [[ "$result" == "ok" ]]
    return
  fi
  # $1 и $2 относятся к внутреннему bash -c, не к этой функции.
  # shellcheck disable=SC2016
  timeout "$timeout_s" bash -c 'echo >/dev/tcp/"$1"/"$2"' bash "$ip" "$port" >/dev/null 2>&1
}

mex_route_exists() {
  local ip="$1"
  if [[ "${MEX_ASSUME_ROUTE:-0}" == "1" ]]; then
    return 0
  fi
  "${MEX_IP_BIN}" route get "$ip" >/dev/null 2>&1
}

mex_tcp_check_exit() {
  local ip="$1"
  local force="$2"
  local ok443=0 ok8443=0
  local missing=""
  if mex_tcp_probe "$ip" 443 5; then
    ok443=1
  else
    missing+=" ${ip}:443"
  fi
  if mex_tcp_probe "$ip" 8443 5; then
    ok8443=1
  else
    missing+=" ${ip}:8443"
  fi
  if (( ok443 == 1 && ok8443 == 1 )); then
    mex_info "TCP ${ip}:443 и TCP ${ip}:8443 доступны. Это только проверка доступности TCP-порта, а не проверка REALITY, VLESS или VPN."
    return 0
  fi
  local msg="Недоступен TCP-порт:${missing}. Это только проверка доступности TCP-порта, а не проверка REALITY, VLESS или VPN."
  if [[ "$force" == "1" ]]; then
    mex_warn "${msg} Exit будет добавлен принудительно (--force)."
    return 0
  fi
  mex_fail "${msg} Операция остановлена. Повторите с --force, только если недоступность порта для вас ожидаема." || true
  return 1
}

mex_exit_allocate_ports() {
  local want1="${1:-}"
  local want2="${2:-}"
  local pair p1 p2
  mex_ports_collect_all || return 1
  if [[ -n "$want1" || -n "$want2" ]]; then
    if [[ -z "$want1" || -z "$want2" ]]; then
      mex_fail "Укажите оба внешних порта Relay: для направления 443 и для направления 8443." || true
      return 1
    fi
    if ! mex_ports_pair_free "$want1" "$want2"; then
      mex_fail "Порты ${want1} и ${want2} нельзя занять: они заняты, совпадают, равны 22 или вне диапазона 1–65535. Занятые порты не перезаписываются." || true
      return 1
    fi
    p1="$want1"
    p2="$want2"
  else
    if ! pair="$(mex_ports_find_free_pair)"; then
      mex_fail "Не удалось найти свободную пару портов Relay в диапазоне 1–65535." || true
      return 1
    fi
    read -r p1 p2 <<<"$pair"
  fi
  MEX_ALLOC_PORT1="$p1"
  MEX_ALLOC_PORT2="$p2"
}

mex_exit_precheck() {
  local name="$1"
  local ip="$2"
  local want1="${3:-}"
  local want2="${4:-}"
  local force="${5:-0}"
  local pub
  if ! mex_valid_name "$name"; then
    mex_fail "Некорректное название сервера. Допустимо до 64 символов без кавычек, обратной косой черты и управляющих символов." || true
    return 1
  fi
  if ! mex_valid_ipv4 "$ip"; then
    mex_fail "Некорректный IPv4-адрес Exit: ${ip}" || true
    return 1
  fi
  mex_config_ensure || return 1
  if mex_config_has_ip "$ip"; then
    mex_fail "Exit с IP ${ip} уже есть в конфигурации. Дубликаты запрещены." || true
    return 1
  fi
  pub="$(jq -r '.public_ip // empty' "$MEX_CONFIG_FILE")"
  if [[ -n "$pub" && "$pub" == "$ip" ]]; then
    mex_fail "IP Exit совпадает с публичным IP Relay (${pub})." || true
    return 1
  fi
  if ! mex_route_exists "$ip"; then
    mex_fail "До IP ${ip} нет маршрута (ip route get ${ip}). Exit не добавлен." || true
    return 1
  fi
  mex_exit_allocate_ports "$want1" "$want2" || return 1
  mex_tcp_check_exit "$ip" "$force" || return 1
}

mex_exit_add() {
  local name="$1"
  local ip="$2"
  local want1="${3:-}"
  local want2="${4:-}"
  local force="${5:-0}"
  local p1 p2 now tmp id rc=0
  mex_require_root || return 1
  mex_acquire_lock || return 1
  mex_exit_precheck "$name" "$ip" "$want1" "$want2" "$force" || return 1
  p1="$MEX_ALLOC_PORT1"
  p2="$MEX_ALLOC_PORT2"
  if [[ "${MEX_SKIP_HOST_INTEGRATION:-0}" != "1" ]]; then
    mex_install_host_integration || return 1
  else
    mex_ensure_sysctl || return 1
  fi
  mex_backup_create "before-add" || return 1
  now="$(mex_timestamp)"
  tmp="$(mktemp)"
  if ! jq \
    --arg name "$name" \
    --arg ip "$ip" \
    --argjson rp1 "$p1" \
    --argjson rp2 "$p2" \
    --arg now "$now" \
    --arg force "$force" \
    '
      .next_seq = (.next_seq // 1)
      | .exits += [{
          id: ("exit-" + (.next_seq | tostring)),
          name: $name,
          host: $ip,
          forwards: [
            {proto: "tcp", listen: $rp1, target: 443},
            {proto: "tcp", listen: $rp2, target: 8443}
          ],
          status: (if $force == "1" then "active-forced" else "active" end),
          added_at: $now,
          tcp_check_forced: ($force == "1")
        }]
      | .next_seq += 1
    ' "$MEX_CONFIG_FILE" >"$tmp"; then
    rm -f "$tmp"
    mex_fail "Не удалось обновить ${MEX_CONFIG_FILE}." || true
    return 1
  fi
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$MEX_CONFIG_FILE"
  id="$(jq -r --arg ip "$ip" '.exits[] | select(.host == $ip) | .id' "$MEX_CONFIG_FILE")"
  mex_apply_from_config || rc=$?
  if (( rc != 0 )); then
    tmp="$(mktemp)"
    jq --arg id "$id" '.exits |= map(select(.id != $id))' "$MEX_CONFIG_FILE" >"$tmp"
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$MEX_CONFIG_FILE"
    mex_iptables_apply_config || true
    mex_fail "Не удалось применить правила для ${id}. Запись об Exit удалена из конфигурации. Чужие правила не изменялись." || true
    return "$rc"
  fi
  mex_info "Exit «${name}» (${ip}) добавлен. Порты Relay: ${p1} -> 443, ${p2} -> 8443. Порты других Exit не изменены."
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    mex_info "Режим dry-run: правила симулированы и в ядро не записывались."
  fi
}

mex_exit_remove() {
  local id="$1"
  local tmp
  mex_require_root || return 1
  mex_acquire_lock || return 1
  mex_config_ensure || return 1
  if ! mex_valid_exit_id "$id"; then
    mex_fail "Некорректный идентификатор Exit: ${id}" || true
    return 1
  fi
  if ! jq -e --arg id "$id" 'any(.exits[]?; .id == $id)' "$MEX_CONFIG_FILE" >/dev/null; then
    mex_fail "Exit ${id} не найден." || true
    return 1
  fi
  mex_backup_create "before-remove-${id}" || return 1
  mex_iptables_remove_exit "$id" || return 1
  tmp="$(mktemp)"
  jq --arg id "$id" '.exits |= map(select(.id != $id))' "$MEX_CONFIG_FILE" >"$tmp"
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$MEX_CONFIG_FILE"
  mex_netfilter_save || true
  mex_info "Exit ${id} удалён. Правила остальных Exit сохранены. Чужие правила файрвола не изменялись."
}

mex_exit_change_ip() {
  local id="$1"
  local new_ip="$2"
  local force="${3:-0}"
  local old_ip backup_cfg tmp
  mex_require_root || return 1
  mex_acquire_lock || return 1
  mex_config_ensure || return 1
  if ! mex_valid_exit_id "$id"; then
    mex_fail "Некорректный идентификатор Exit: ${id}" || true
    return 1
  fi
  if ! mex_valid_ipv4 "$new_ip"; then
    mex_fail "Некорректный IPv4-адрес: ${new_ip}" || true
    return 1
  fi
  if ! jq -e --arg id "$id" 'any(.exits[]?; .id == $id)' "$MEX_CONFIG_FILE" >/dev/null; then
    mex_fail "Exit ${id} не найден." || true
    return 1
  fi
  old_ip="$(jq -r --arg id "$id" '.exits[] | select(.id == $id) | .host' "$MEX_CONFIG_FILE")"
  if [[ "$old_ip" == "$new_ip" ]]; then
    mex_info "IP Exit ${id} уже равен ${new_ip}. Порты не изменялись."
    return 0
  fi
  if mex_config_has_ip "$new_ip"; then
    mex_fail "IP ${new_ip} уже используется другим Exit." || true
    return 1
  fi
  local pub
  pub="$(jq -r '.public_ip // empty' "$MEX_CONFIG_FILE")"
  if [[ -n "$pub" && "$pub" == "$new_ip" ]]; then
    mex_fail "Новый IP совпадает с публичным IP Relay." || true
    return 1
  fi
  if ! mex_route_exists "$new_ip"; then
    mex_fail "До IP ${new_ip} нет маршрута. IP не изменён, порты сохранены." || true
    return 1
  fi
  mex_tcp_check_exit "$new_ip" "$force" || return 1
  mex_backup_create "before-change-ip-${id}" || return 1
  backup_cfg="${MEX_LAST_BACKUP}/config.json"
  tmp="$(mktemp)"
  jq --arg id "$id" --arg ip "$new_ip" --arg now "$(mex_timestamp)" --arg force "$force" '
    .exits |= map(
      if .id == $id then
        .host = $ip
        | .status = (if $force == "1" then "active-forced" else "active" end)
        | .tcp_check_forced = ($force == "1")
        | .updated_at = $now
      else
        .
      end
    )
  ' "$MEX_CONFIG_FILE" >"$tmp"
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$MEX_CONFIG_FILE"
  if ! mex_apply_from_config; then
    cp -a "$backup_cfg" "$MEX_CONFIG_FILE"
    mex_iptables_apply_config || true
    mex_fail "Не удалось сменить IP. Восстановлена предыдущая конфигурация ${id}, порты не менялись." || true
    return 1
  fi
  mex_info "IP Exit ${id} изменён с ${old_ip} на ${new_ip}. Порты Relay сохранены."
}

mex_status_ru() {
  case "${1:-}" in
    active) printf '%s' "активен" ;;
    active-forced) printf '%s' "активен (принудительно)" ;;
    *) printf '%s' "${1:-}" ;;
  esac
}

mex_exit_print_table() {
  local name ip p1 p2 status
  if [[ ! -f "$MEX_CONFIG_FILE" ]]; then
    mex_info "Конфигурация ещё не создана."
    return 0
  fi
  if ! jq -e '.exits | length > 0' "$MEX_CONFIG_FILE" >/dev/null; then
    mex_info "Список Exit пуст."
    return 0
  fi
  {
    printf 'СТРАНА\tHOST\tПРОБРОС\tСТАТУС\n'
    while IFS=$'\t' read -r name host forwards status; do
      [[ -n "$name" ]] || continue
      printf '%s\t%s\t%s\t%s\n' "$name" "$host" "$forwards" "$(mex_status_ru "$status")"
    done < <(jq -r '.exits[] | [.name, .host, ([.forwards[]? | "\(.proto)/\(.listen)->\(.target)"] | join(", ")), (.status // "active")] | @tsv' "$MEX_CONFIG_FILE")
  } | if command -v column >/dev/null 2>&1; then
    column -t -s $'\t'
  else
    cat
  fi
}

mex_exit_describe_links() {
  local pub name ip p1 p2
  pub="$(jq -r '.public_ip // "IP_RELAY"' "$MEX_CONFIG_FILE" 2>/dev/null || printf '%s' "IP_RELAY")"
  mex_info "Клиентская ссылка берётся на Exit. Замените адрес на ${pub} и порт на порт Relay для нужного проброса. SNI, ключи и пароли не меняйте. UDP (Hysteria2/QUIC) использует UDP-порт Relay."
  while IFS=$'\t' read -r name host proto listen target; do
    [[ -n "$host" ]] || continue
    mex_info "  ${name}: ${proto} ${host}:${target} -> ${pub}:${listen}"
  done < <(jq -r '.exits[] | .name as $n | .host as $h | .forwards[]? | [$n, $h, .proto, (.listen|tostring), (.target|tostring)] | @tsv' "$MEX_CONFIG_FILE")
}

mex_ensure_sysctl() {
  local tmp dir
  dir="$(dirname "$MEX_SYSCTL_FILE")"
  mkdir -p "$dir"
  tmp="$(mktemp "${MEX_SYSCTL_FILE}.XXXXXX")"
  cat >"$tmp" <<'EOF'
# Multi-Exit Relay: включить пересылку IPv4.
# Файл создаётся установщиком и удаляется при удалении установки,
# если кроме этой настройки в нём ничего нет.
net.ipv4.ip_forward=1
EOF
  chmod 644 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$MEX_SYSCTL_FILE"
  if [[ "${MEX_DRY_RUN:-0}" == "1" || "${MEX_SKIP_SYSCTL_APPLY:-0}" == "1" ]]; then
    return 0
  fi
  "${MEX_SYSCTL_BIN}" -w net.ipv4.ip_forward=1 >/dev/null
}

mex_remove_sysctl_if_ours() {
  local body
  [[ -f "$MEX_SYSCTL_FILE" ]] || return 0
  body="$(grep -v -E '^[[:space:]]*#' "$MEX_SYSCTL_FILE" | grep -v -E '^[[:space:]]*$' || true)"
  if [[ "$body" == "net.ipv4.ip_forward=1" ]]; then
    rm -f "$MEX_SYSCTL_FILE"
    mex_info "Удалён ${MEX_SYSCTL_FILE}. Значение net.ipv4.ip_forward не сбрасывалось в 0."
  else
    mex_warn "Файл ${MEX_SYSCTL_FILE} содержит дополнительные настройки и не удалён."
  fi
}

mex_systemd_unit_text() {
  local bin="${MEX_INSTALL_DIR}/relay"
  cat <<EOF
[Unit]
Description=Multi-Exit Relay: повторное применение правил проброса
After=network-online.target netfilter-persistent.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${bin} apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
}

mex_systemd_resolve_service_text() {
  local bin="${MEX_INSTALL_DIR}/relay"
  cat <<EOF
[Unit]
Description=Multi-Exit Relay: повторный резолв имён Exit и сверка правил
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${bin} apply
EOF
}

mex_systemd_resolve_timer_text() {
  cat <<'EOF'
[Unit]
Description=Multi-Exit Relay: периодический резолв имён Exit

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

mex_systemd_paths() {
  local dir
  dir="$(dirname "$MEX_SYSTEMD_UNIT")"
  MEX_SYSTEMD_RESOLVE_SERVICE="${dir}/multi-exit-relay-resolve.service"
  MEX_SYSTEMD_RESOLVE_TIMER="${dir}/multi-exit-relay-resolve.timer"
}

mex_install_systemd() {
  local unit
  [[ "${MEX_SKIP_SYSTEMD:-0}" == "1" ]] && return 0
  unit="$MEX_SYSTEMD_UNIT"
  mex_systemd_paths
  mkdir -p "$(dirname "$unit")"
  mex_systemd_unit_text >"$unit"
  mex_systemd_resolve_service_text >"$MEX_SYSTEMD_RESOLVE_SERVICE"
  mex_systemd_resolve_timer_text >"$MEX_SYSTEMD_RESOLVE_TIMER"
  chmod 644 "$unit" "$MEX_SYSTEMD_RESOLVE_SERVICE" "$MEX_SYSTEMD_RESOLVE_TIMER" 2>/dev/null || true
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    mex_log INFO "dry-run: systemctl не вызывался, юниты записаны в $(dirname "$unit")"
    return 0
  fi
  if ! mex_have systemctl; then
    mex_warn "systemctl не найден. Юниты записаны в $(dirname "$unit"), но не включены."
    return 0
  fi
  systemctl daemon-reload
  systemctl enable multi-exit-relay.service
  systemctl enable --now multi-exit-relay-resolve.timer
  mex_info "Служба multi-exit-relay.service включена. Таймер multi-exit-relay-resolve.timer каждые 5 минут заново разрешает имена Exit и сверяет правила."
}

mex_remove_systemd() {
  [[ "${MEX_SKIP_SYSTEMD:-0}" == "1" ]] && return 0
  mex_systemd_paths
  if [[ "${MEX_DRY_RUN:-0}" != "1" ]] && mex_have systemctl; then
    systemctl disable --now multi-exit-relay-resolve.timer >/dev/null 2>&1 || true
    systemctl disable --now multi-exit-relay-resolve.service >/dev/null 2>&1 || true
    systemctl disable --now multi-exit-relay.service >/dev/null 2>&1 || true
    rm -f "$MEX_SYSTEMD_UNIT" "$MEX_SYSTEMD_RESOLVE_SERVICE" "$MEX_SYSTEMD_RESOLVE_TIMER"
    systemctl daemon-reload >/dev/null 2>&1 || true
  else
    rm -f "$MEX_SYSTEMD_UNIT" "$MEX_SYSTEMD_RESOLVE_SERVICE" "$MEX_SYSTEMD_RESOLVE_TIMER"
  fi
  mex_info "Служба multi-exit-relay и таймер резолва отключены."
}

mex_sync_install_tree() {
  local src dest item
  src="${MEX_SOURCE_DIR:-}"
  dest="${MEX_INSTALL_DIR}"
  if [[ -z "$src" || ! -f "$src/relay" ]]; then
    mex_warn "Каталог исходников не найден. Файлы программы не скопированы в ${dest}."
    return 0
  fi
  if [[ "$(readlink -f "$src")" == "$(readlink -f "$dest")" ]]; then
    return 0
  fi
  mkdir -p "$dest"
  for item in install.sh uninstall.sh relay lib config LICENSE README.md; do
    [[ -e "$src/$item" ]] || continue
    rm -rf "${dest:?}/$item"
    cp -a "$src/$item" "$dest/$item"
  done
  chmod 755 "$dest/install.sh" "$dest/uninstall.sh" "$dest/relay" "$dest"/lib/*.sh
}

mex_install_cli() {
  local src full short current ours
  [[ "${MEX_SKIP_CLI:-0}" == "1" ]] && return 0
  mkdir -p "$MEX_BIN_DIR"
  src="${MEX_INSTALL_DIR}/relay"
  full="${MEX_BIN_DIR}/multi-exit-relay"
  short="${MEX_BIN_DIR}/relay"
  ln -sfn "$src" "$full"
  if [[ -e "$short" || -L "$short" ]]; then
    current="$(readlink -f "$short" 2>/dev/null || true)"
    ours="$(readlink -f "$src" 2>/dev/null || true)"
    if [[ -n "$ours" && "$current" == "$ours" ]]; then
      ln -sfn "$src" "$short"
    elif [[ -L "$short" && "$(readlink "$short")" == "$src" ]]; then
      ln -sfn "$src" "$short"
    else
      mex_warn "Файл ${short} уже существует и не принадлежит Multi-Exit Relay (${current:-другая программа}). Он не перезаписан. Используйте команду multi-exit-relay."
      return 0
    fi
  else
    ln -sfn "$src" "$short"
  fi
  mex_info "Команды установлены: ${full} и, если путь был свободен, ${short}."
}

mex_remove_cli() {
  local path src target current ours
  [[ "${MEX_SKIP_CLI:-0}" == "1" ]] && return 0
  src="${MEX_INSTALL_DIR}/relay"
  ours="$(readlink -f "$src" 2>/dev/null || true)"
  for path in "${MEX_BIN_DIR}/relay" "${MEX_BIN_DIR}/multi-exit-relay"; do
    [[ -L "$path" ]] || continue
    target="$(readlink "$path" || true)"
    current="$(readlink -f "$path" 2>/dev/null || true)"
    if [[ "$target" == "$src" || ( -n "$ours" && "$current" == "$ours" ) ]]; then
      rm -f "$path"
      mex_info "Удалена ссылка ${path}."
    else
      mex_warn "Ссылка ${path} ведёт на другую программу и не удалена."
    fi
  done
}

mex_install_host_integration() {
  mex_sync_install_tree || return 1
  mex_ensure_sysctl || return 1
  mex_install_systemd || return 1
  mex_install_cli || return 1
  local cur="{}"
  mex_ensure_dirs
  if [[ -f "$MEX_STATE_FILE" ]]; then
    cur="$(cat "$MEX_STATE_FILE")"
  fi
  jq -n --argjson cur "$cur" --arg now "$(mex_timestamp)" --arg dir "$MEX_INSTALL_DIR" '
    $cur + {
      version: 1,
      updated_at: $now,
      install_dir: $dir,
      sysctl_managed: true,
      systemd_managed: true
    }
  ' | mex_atomic_write "$MEX_STATE_FILE"
}

mex_netfilter_save() {
  if [[ -n "${MEX_NETFILTER_SAVE_CMD:-}" ]]; then
    bash -c "$MEX_NETFILTER_SAVE_CMD"
    return $?
  fi
  if [[ "${MEX_SKIP_NETFILTER_SAVE:-0}" == "1" || "${MEX_DRY_RUN:-0}" == "1" ]]; then
    mex_log INFO "Сохранение netfilter пропущено."
    return 0
  fi
  if mex_have netfilter-persistent; then
    netfilter-persistent save
    mex_info "Правила сохранены через netfilter-persistent."
    return 0
  fi
  mex_warn "netfilter-persistent не установлен. Правила действуют до перезагрузки. Если служба multi-exit-relay включена, она применит config.json при загрузке."
  return 0
}

mex_apply_install_config_file() {
  local src="$1"
  local ver tmp
  [[ -n "$src" ]] || return 0
  if [[ ! -f "$src" ]]; then
    mex_json_error 2 config_missing "Файл конфигурации не найден: ${src}" || return $?
  fi
  if ! jq -e . "$src" >/dev/null 2>&1; then
    mex_json_error 2 config_invalid "Файл ${src} не является JSON. Текущая конфигурация не заменена." || return $?
  fi
  ver="$(jq -r '.version // empty' "$src" 2>/dev/null || true)"
  case "$ver" in
    1|2) ;;
    *)
      mex_json_error 2 config_invalid "В ${src} неподдерживаемая версия схемы. Текущая конфигурация не заменена." || return $?
      ;;
  esac
  if ! mex_config_validate_file "$src"; then
    local err="${MEX_CONFIG_ERROR:-config_invalid}"
    mex_json_error 2 "$err" "Файл ${src} не прошёл проверку. Текущая конфигурация не заменена." || return $?
  fi
  mex_ensure_dirs
  if [[ -f "$MEX_CONFIG_FILE" ]] && [[ "$(readlink -f "$src")" == "$(readlink -f "$MEX_CONFIG_FILE")" ]]; then
    return 0
  fi
  tmp="$(mktemp)"
  cp -a "$src" "$tmp"
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$MEX_CONFIG_FILE"
  return 0
}

mex_apply_emit_json() {
  [[ "${MEX_JSON:-0}" == "1" ]] || return 0
  local exits forwards
  exits="$(jq -r '.exits | length' "$MEX_CONFIG_FILE")"
  forwards="$(jq -r '[.exits[].forwards[]?] | length' "$MEX_CONFIG_FILE")"
  jq -n \
    --arg version "$MEX_VERSION" \
    --arg config_file "$MEX_CONFIG_FILE" \
    --argjson config_version 2 \
    --argjson exits "$exits" \
    --argjson forwards "$forwards" \
    --argjson added "${MEX_RULES_ADDED:-0}" \
    --argjson removed "${MEX_RULES_REMOVED:-0}" \
    --argjson unchanged "${MEX_RULES_UNCHANGED:-0}" \
    '{
      ok: true,
      command: "apply",
      version: $version,
      config_file: $config_file,
      config_version: $config_version,
      exits: $exits,
      forwards: $forwards,
      rules_added: $added,
      rules_removed: $removed,
      rules_unchanged: $unchanged
    }'
}

mex_apply_from_config() {
  local rc=0
  MEX_INFO_STDERR=1
  if [[ "${MEX_OPT_JSON:-0}" == "1" ]]; then
    MEX_JSON=1
    MEX_JSON_COMMAND="apply"
  fi
  mex_require_root || {
    mex_json_error 3 permission "Нужны права root." || return $?
  }
  if ! mex_acquire_lock; then
    if [[ "${MEX_JSON:-0}" == "1" ]] && command -v jq >/dev/null 2>&1; then
      jq -n \
        --arg version "$MEX_VERSION" \
        --arg config_file "${MEX_CONFIG_FILE:-}" \
        '{
          ok: false,
          command: "apply",
          error: "lock_busy",
          message: "Уже выполняется другой экземпляр Multi-Exit Relay.",
          version: $version,
          config_file: $config_file,
          problems: [{code: "lock_busy"}]
        }'
    fi
    return 5
  fi
  if [[ -n "${MEX_OPT_CONFIG:-}" ]]; then
    mex_apply_install_config_file "$MEX_OPT_CONFIG" || return $?
  fi
  if [[ ! -f "$MEX_CONFIG_FILE" ]]; then
    mex_json_error 2 config_missing "Конфигурация отсутствует: ${MEX_CONFIG_FILE}" || return $?
  fi
  if ! mex_ensure_sysctl; then
    mex_json_error 3 apply_failed "Не удалось включить net.ipv4.ip_forward." || return $?
  fi
  mex_iptables_apply_config || rc=$?
  if (( rc != 0 )); then
    return "$rc"
  fi
  mex_netfilter_save || true
  mex_apply_emit_json
  mex_info "Правила применены из ${MEX_CONFIG_FILE}."
  return 0
}

mex_install_packages_noninteractive() {
  [[ "${MEX_SKIP_DEPS:-0}" == "1" || "${MEX_DRY_RUN:-0}" == "1" ]] && return 0
  if ! mex_have apt-get; then
    mex_json_error 3 dependency "Нужен apt-get (Ubuntu 22.04 или 24.04)." || return $?
  fi
  export DEBIAN_FRONTEND=noninteractive
  echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
  if ! apt-get update -y; then
    mex_json_error 3 dependency "apt-get update завершился с ошибкой." || return $?
  fi
  if ! apt-get install -y jq iptables iproute2 curl ca-certificates iptables-persistent coreutils util-linux procps; then
    mex_json_error 3 dependency "Не удалось установить пакеты Multi-Exit Relay." || return $?
  fi
  return 0
}

mex_install_noninteractive() {
  local n=0
  mex_require_root || {
    mex_json_error 3 permission "Нужны права root." || return $?
  }
  if ! mex_os_is_supported; then
    mex_json_error 3 unsupported_os "Нужна Ubuntu 22.04 или 24.04." || return $?
  fi
  mex_install_packages_noninteractive || return $?
  mex_require_iptables || {
    mex_json_error 3 dependency "Команда iptables недоступна." || return $?
  }
  mex_acquire_lock || return $?
  mex_ensure_dirs
  if [[ -f "$MEX_CONFIG_FILE" ]]; then
    if ! mex_config_validate_file "$MEX_CONFIG_FILE"; then
      mex_json_error 2 config_invalid "Существующий ${MEX_CONFIG_FILE} повреждён. Файл не перезаписан." || return $?
    fi
    if [[ "$(jq -r '.version // empty' "$MEX_CONFIG_FILE")" == "1" ]]; then
      if ! mex_config_migrate_inplace "$MEX_CONFIG_FILE"; then
        mex_json_error 2 config_invalid "Не удалось перевести существующий config.json на схему v2." || return $?
      fi
    fi
  else
    if [[ -z "${MEX_EGRESS_IFACE:-}" ]]; then
      MEX_EGRESS_IFACE="$(mex_detect_egress_iface 2>/dev/null || true)"
    fi
    if [[ -z "${MEX_PUBLIC_IP:-}" ]]; then
      MEX_PUBLIC_IP="$(mex_detect_public_ip 2>/dev/null || true)"
    fi
    mex_config_ensure || {
      mex_json_error 3 apply_failed "Не удалось создать ${MEX_CONFIG_FILE}." || return $?
    }
  fi
  mex_install_host_integration || {
    mex_json_error 3 apply_failed "Не удалось установить службу и команду relay." || return $?
  }
  n="$(jq -r '[.exits[]?.forwards[]?] | length' "$MEX_CONFIG_FILE" 2>/dev/null || printf '0')"
  if [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )); then
    mex_apply_from_config || return $?
  fi
  mex_info "Установка без вопросов завершена. Команда: relay. Конфигурация: ${MEX_CONFIG_FILE}."
  return 0
}

mex_show_firewall_summary() {
  local fwd natp natpo
  fwd="$(mex_iptables -S FORWARD 2>/dev/null | awk '/^-A /{c++} END{print c+0}')"
  natp="$(mex_iptables -t nat -S PREROUTING 2>/dev/null | awk '/^-A /{c++} END{print c+0}')"
  natpo="$(mex_iptables -t nat -S POSTROUTING 2>/dev/null | awk '/^-A /{c++} END{print c+0}')"
  mex_info "Текущие правила не будут удалены. Сейчас правил: FORWARD=${fwd}, NAT PREROUTING=${natp}, NAT POSTROUTING=${natpo}."
  if mex_have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    mex_info "UFW активен и не будет отключён. Разрешение проброса ставится цепочкой MEX_FORWARD в начало FORWARD."
  fi
}

mex_ensure_dependencies() {
  local -a missing=()
  [[ "${MEX_SKIP_DEPS:-0}" == "1" || "${MEX_DRY_RUN:-0}" == "1" ]] && return 0
  mex_have jq || missing+=("jq")
  mex_have iptables || missing+=("iptables")
  mex_have ip || missing+=("iproute2")
  mex_have ss || missing+=("iproute2")
  mex_have timeout || missing+=("coreutils")
  mex_have flock || missing+=("util-linux")
  mex_have curl || missing+=("curl")
  mex_have sysctl || missing+=("procps")
  if ((${#missing[@]} > 0)); then
    local uniq
    uniq="$(printf '%s\n' "${missing[@]}" | awk '!seen[$0]++' | paste -sd' ' -)"
    mex_confirm "Установить пакеты: ${uniq}?" || {
      mex_fail "Без этих пакетов установка невозможна." || true
      return 1
    }
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y $uniq
  fi
  if ! mex_have netfilter-persistent && ! dpkg -s iptables-persistent >/dev/null 2>&1; then
    if mex_confirm "Установить iptables-persistent, чтобы правила сохранялись после перезагрузки?"; then
      echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
      echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
      DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
      jq -n --arg now "$(mex_timestamp)" '{version:1, updated_at:$now, iptables_persistent_installed_by_us:true}' \
        | mex_atomic_write "$MEX_STATE_FILE"
    else
      mex_warn "Без netfilter-persistent правила пропадут после перезагрузки, если не сработает служба multi-exit-relay."
    fi
  fi
}

mex_require_iptables() {
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    return 0
  fi
  if ! mex_have "$MEX_IPTABLES" && ! mex_have iptables; then
    mex_fail "Команда iptables не найдена." || true
    return 1
  fi
  if ! mex_iptables -S >/dev/null; then
    mex_fail "Не удалось выполнить iptables. Нужны root и рабочий iptables, в том числе iptables-nft." || true
    return 1
  fi
}

mex_uninstall_system() {
  mex_require_root || return 1
  mex_acquire_lock || return 1
  mex_backup_create "before-uninstall" || return 1
  mex_iptables_uninstall || return 1
  mex_netfilter_save || true
  mex_remove_sysctl_if_ours
  mex_remove_systemd
  mex_remove_cli
  mex_info "Удалены только правила и цепочки Multi-Exit Relay, его sysctl-файл, служба и ссылки команд. Чужие правила NAT и файрвола не изменялись. Резервные копии сохранены: ${MEX_BACKUP_DIR}."
}

mex_uninstall_config_files() {
  rm -f "$MEX_CONFIG_FILE" "$MEX_STATE_FILE"
  mex_info "Удалены config.json и state.json. Каталог резервных копий сохранён: ${MEX_BACKUP_DIR}."
}

mex_pick_exit_id() {
  local choice id count
  local -a ids=()
  mapfile -t ids < <(jq -r '.exits[].id' "$MEX_CONFIG_FILE")
  count="${#ids[@]}"
  if (( count == 0 )); then
    mex_fail "Список Exit пуст." || true
    return 1
  fi
  mex_exit_print_table
  local i=1
  for id in "${ids[@]}"; do
    printf '%d) %s\n' "$i" "$id"
    i=$((i + 1))
  done
  mex_prompt choice "Номер Exit: " || return 1
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > count )); then
    mex_fail "Нет пункта ${choice}." || true
    return 1
  fi
  MEX_PICKED_ID="${ids[$((choice - 1))]}"
}

mex_wizard_add_one() {
  local name ip ports p1="" p2="" force=0
  mex_prompt name "Название сервера (страна или метка): " || return 1
  mex_prompt ip "IP сервера: " || return 1
  mex_prompt ports "Внешние порты Relay для 443 и 8443 через пробел (Enter — автоматически): " || return 1
  if [[ -n "$ports" ]]; then
    read -r p1 p2 _extra <<<"$ports"
    if [[ -z "$p1" || -z "$p2" || -n "${_extra:-}" ]]; then
      mex_fail "Нужны ровно два порта, например: 443 8443" || true
      return 1
    fi
  fi
  if ! mex_exit_precheck "$name" "$ip" "$p1" "$p2" 0; then
    if mex_confirm "TCP-проверка не пройдена или есть другое препятствие. Если причина только в TCP-порте, добавить принудительно? Это не проверка VPN."; then
      force=1
      mex_exit_precheck "$name" "$ip" "$p1" "$p2" 1 || return 1
    else
      return 1
    fi
  fi
  mex_info "Будет добавлен Exit «${name}» ${ip}: порты Relay ${MEX_ALLOC_PORT1} и ${MEX_ALLOC_PORT2}."
  mex_confirm "Добавить этот Exit?" || {
    mex_info "Отменено. Существующие Exit не изменены."
    return 1
  }
  mex_exit_add "$name" "$ip" "$MEX_ALLOC_PORT1" "$MEX_ALLOC_PORT2" "$force"
}

mex_wizard_remove() {
  local id name
  mex_config_ensure || return 1
  mex_pick_exit_id || return 1
  id="$MEX_PICKED_ID"
  name="$(jq -r --arg id "$id" '.exits[] | select(.id == $id) | .name' "$MEX_CONFIG_FILE")"
  mex_warn "Будут удалены только правила Exit «${name}» (${id}). Остальные Exit и чужие правила файрвола не изменятся."
  mex_confirm "Удалить ${id}?" || {
    mex_info "Удаление отменено."
    return 1
  }
  mex_exit_remove "$id"
}

mex_wizard_change_ip() {
  local id new_ip force=0
  mex_config_ensure || return 1
  mex_pick_exit_id || return 1
  id="$MEX_PICKED_ID"
  mex_prompt new_ip "Новый IP для ${id} (порты Relay сохранятся): " || return 1
  if ! mex_valid_ipv4 "$new_ip"; then
    mex_fail "Некорректный IPv4-адрес: ${new_ip}" || true
    return 1
  fi
  mex_info "Порты Relay у ${id} останутся прежними. Изменится только IP ${new_ip}."
  mex_confirm "Сменить IP Exit ${id}?" || {
    mex_info "Смена IP отменена."
    return 1
  }
  if ! mex_exit_change_ip "$id" "$new_ip" 0; then
    if mex_confirm "Повторить смену IP принудительно, если не прошла только TCP-проверка?"; then
      force=1
      mex_exit_change_ip "$id" "$new_ip" "$force"
    else
      return 1
    fi
  fi
}

mex_wizard_restore() {
  local -a items=()
  local choice dir
  mapfile -t items < <(mex_backup_list | sort) || {
    mex_info "Резервных копий нет."
    return 1
  }
  if ((${#items[@]} == 0)); then
    mex_info "Резервных копий нет."
    return 1
  fi
  local i=1
  for dir in "${items[@]}"; do
    printf '%d) %s\n' "$i" "$dir"
    i=$((i + 1))
  done
  mex_prompt choice "Номер копии: " || return 1
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#items[@]} )); then
    mex_fail "Нет такой копии." || true
    return 1
  fi
  dir="${MEX_BACKUP_DIR}/${items[$((choice - 1))]}"
  mex_warn "Будет заново собран только проброс Multi-Exit Relay из сохранённого config.json. Весь файрвол из снимка iptables не восстанавливается."
  mex_confirm "Восстановить ${dir}?" || return 1
  mex_backup_restore "$dir"
}

mex_prompt_exit_row() {
  local __name_var="$1" __ip_var="$2" __p1_var="$3" __p2_var="$4"
  local name ip ports p1="" p2=""
  mex_prompt name "Название сервера (страна или метка): " || return 1
  mex_prompt ip "IP сервера: " || return 1
  mex_prompt ports "Внешние порты Relay для 443 и 8443 через пробел (Enter — автоматически): " || return 1
  if [[ -n "$ports" ]]; then
    local extra=""
    read -r p1 p2 extra <<<"$ports"
    if [[ -z "${p1}" || -z "${p2}" || -n "$extra" ]]; then
      mex_fail "Нужны ровно два порта, например: 10443 18443" || true
      return 1
    fi
  fi
  printf -v "$__name_var" '%s' "$name"
  printf -v "$__ip_var" '%s' "$ip"
  printf -v "$__p1_var" '%s' "$p1"
  printf -v "$__p2_var" '%s' "$p2"
}

mex_wizard_install() {
  local id ver iface ip detected_iface detected_ip
  local -a pending_name=() pending_ip=() pending_p1=() pending_p2=() pending_force=()
  local planned_ports="" more="Y"
  if ! mex_os_is_supported; then
    read -r id ver < <(mex_detect_os || true)
    mex_warn "Обнаружена система ${id:-неизвестно} ${ver:-}. Установщик рассчитан на Ubuntu 22.04 и 24.04."
    mex_confirm "Продолжить несмотря на версию системы?" || return 1
  else
    read -r id ver < <(mex_detect_os || true)
    mex_info "Система: ${id} ${ver}."
  fi
  mex_ensure_dependencies || return 1
  mex_require_iptables || return 1
  if ! detected_iface="$(mex_detect_egress_iface)"; then
    detected_iface=""
  fi
  mex_prompt iface "Интерфейс выхода [${detected_iface:-не найден}]: " "$detected_iface" || return 1
  if ! mex_valid_iface_name "$iface"; then
    mex_fail "Некорректное имя интерфейса: ${iface}" || true
    return 1
  fi
  if [[ "${MEX_DRY_RUN:-0}" != "1" ]] && ! "${MEX_IP_BIN}" link show "$iface" >/dev/null 2>&1; then
    mex_fail "Интерфейс ${iface} не найден." || true
    return 1
  fi
  MEX_EGRESS_IFACE="$iface"
  if ! detected_ip="$(mex_detect_public_ip)"; then
    detected_ip=""
  fi
  mex_prompt ip "Публичный IPv4 Relay [${detected_ip:-не определён}]: " "$detected_ip" || return 1
  if ! mex_valid_ipv4 "$ip"; then
    mex_fail "Некорректный публичный IPv4 Relay: ${ip}" || true
    return 1
  fi
  if mex_is_private_ipv4 "$ip"; then
    mex_warn "Адрес ${ip} выглядит как частный. Для клиентов обычно нужен публичный адрес Relay."
  fi
  MEX_PUBLIC_IP="$ip"
  mex_info "Relay: интерфейс ${iface}, IP ${ip}."
  mex_show_firewall_summary || return 1
  mex_config_ensure || return 1
  mex_config_set_host "$ip" "$iface" || return 1

  while [[ "$more" == "Y" ]]; do
    local name eip p1 p2 force=0 seen=""
    MEX_PLANNED_PORTS="$planned_ports"
    mex_prompt_exit_row name eip p1 p2 || return 1
    for seen in "${pending_ip[@]}"; do
      if [[ "$seen" == "$eip" ]]; then
        mex_fail "IP ${eip} уже есть в списке этой установки. Дубликаты запрещены." || true
        return 1
      fi
    done
    if mex_exit_precheck "$name" "$eip" "$p1" "$p2" 0; then
      force=0
    else
      if mex_confirm "Не добавлять этот Exit автоматически. Принудительно оставить его в списке, если не прошла только TCP-проверка?"; then
        force=1
        mex_exit_precheck "$name" "$eip" "$p1" "$p2" 1 || return 1
      else
        mex_info "Exit пропущен."
        if ! mex_confirm_default_yes "Добавить ещё один Exit?"; then
          more="N"
        fi
        continue
      fi
    fi
    pending_name+=("$name")
    pending_ip+=("$eip")
    pending_p1+=("$MEX_ALLOC_PORT1")
    pending_p2+=("$MEX_ALLOC_PORT2")
    pending_force+=("$force")
    planned_ports+=" ${MEX_ALLOC_PORT1} ${MEX_ALLOC_PORT2}"
    mex_info "В список: ${name} ${eip} порты ${MEX_ALLOC_PORT1} и ${MEX_ALLOC_PORT2}."
    if mex_confirm_default_yes "Добавить ещё один Exit?"; then
      more="Y"
    else
      more="N"
    fi
  done
  unset MEX_PLANNED_PORTS

  if ((${#pending_name[@]} == 0)); then
    mex_info "Новые Exit не заданы."
  else
    printf '\n%s\n' "Проверьте таблицу. Правила ещё не применены."
    local i table
    table="$(mktemp)"
    {
      printf 'СТРАНА\tIP EXIT\tПОРТ RELAY 1\tПОРТ RELAY 2\tСТАТУС\n'
      for i in "${!pending_name[@]}"; do
        local st="активен"
        if [[ "${pending_force[$i]}" == "1" ]]; then
          st="активен (принудительно)"
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "${pending_name[$i]}" "${pending_ip[$i]}" "${pending_p1[$i]}" "${pending_p2[$i]}" "$st"
      done
    } >"$table"
    if command -v column >/dev/null 2>&1; then
      column -t -s $'\t' <"$table"
    else
      cat "$table"
    fi
    rm -f "$table"
  fi
  mex_confirm "Применить настройку Relay и правила проброса?" || {
    mex_info "Установка отменена. Чужие правила файрвола не изменялись."
    if [[ -f "$MEX_CONFIG_FILE" ]] && jq -e '.exits | length == 0' "$MEX_CONFIG_FILE" >/dev/null 2>&1; then
      rm -f "$MEX_CONFIG_FILE"
    fi
    return 1
  }
  mex_backup_create "before-install" || return 1
  mex_install_host_integration || return 1
  mex_iptables_ensure_base || return 1
  for i in "${!pending_name[@]}"; do
    mex_exit_add "${pending_name[$i]}" "${pending_ip[$i]}" "${pending_p1[$i]}" "${pending_p2[$i]}" "${pending_force[$i]}" || return 1
  done
  mex_netfilter_save || true
  mex_info "Установка завершена."
  if ((${#pending_name[@]} > 0)); then
    mex_exit_describe_links
  fi
}
