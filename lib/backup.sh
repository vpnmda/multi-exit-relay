#!/usr/bin/env bash
# Резервные копии перед изменениями.
# Восстановление заново собирает только правила Multi-Exit Relay из сохранённого config.json.
# Полный снимок iptables хранится для просмотра и не заливается обратно в ядро.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_BACKUP_LOADED:-}" ]] && return 0
MEX_BACKUP_LOADED=1

# shellcheck source=iptables.sh
source "$(dirname "${BASH_SOURCE[0]}")/iptables.sh"

mex_backup_create() {
  local reason="${1:-manual}"
  local ts dir
  reason="${reason//[^A-Za-z0-9._-]/_}"
  mex_ensure_dirs
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  dir="${MEX_BACKUP_DIR}/${ts}-${reason}"
  if [[ -e "$dir" ]]; then
    dir="${dir}-$$"
  fi
  mkdir -p "$dir"
  if [[ "${MEX_DRY_RUN:-0}" == "1" ]]; then
    {
      printf '%s\n' "# dry-run: снимок симулятора, ядро не читалось"
      printf '%s\n' "*filter"
      mex_iptables -S 2>/dev/null || true
      printf '%s\n' "*nat"
      mex_iptables -t nat -S 2>/dev/null || true
      printf '%s\n' "*mangle"
      mex_iptables -t mangle -S 2>/dev/null || true
    } >"$dir/iptables.v4"
    printf '%s\n' "dry-run: ip6tables не изменялись" >"$dir/ip6tables.v6"
  else
    if ! "${MEX_IPTABLES_SAVE}" >"$dir/iptables.v4"; then
      mex_fail "Не удалось выполнить iptables-save. Изменения не применены." || true
      return 1
    fi
    if ! "${MEX_IP6TABLES_SAVE}" >"$dir/ip6tables.v6" 2>"$dir/ip6tables.err"; then
      printf '%s\n' "ip6tables-save завершился с ошибкой, см. ip6tables.err" >>"$dir/ip6tables.v6"
    fi
  fi
  if [[ -f "$MEX_SYSCTL_FILE" ]]; then
    cp -a "$MEX_SYSCTL_FILE" "$dir/sysctl.txt"
  elif [[ "${MEX_DRY_RUN:-0}" != "1" ]]; then
    "${MEX_SYSCTL_BIN}" net.ipv4.ip_forward >"$dir/sysctl.txt" 2>/dev/null || true
  else
    printf '%s\n' "net.ipv4.ip_forward=(файл sysctl ещё не создан)" >"$dir/sysctl.txt"
  fi
  if [[ -f "$MEX_CONFIG_FILE" ]]; then
    cp -a "$MEX_CONFIG_FILE" "$dir/config.json"
  else
    printf '%s\n' '{"version":1,"exits":[]}' >"$dir/config.json"
  fi
  if [[ -f "$MEX_STATE_FILE" ]]; then
    cp -a "$MEX_STATE_FILE" "$dir/state.json"
  fi
  printf '%s\n' "$reason" >"$dir/reason.txt"
  printf '%s\n' "$(mex_timestamp)" >"$dir/created_at.txt"
  # shellcheck disable=SC2034
  MEX_LAST_BACKUP="$dir"
  mex_info "Резервная копия: ${dir}"
}

mex_backup_list() {
  local dir base
  mex_ensure_dirs
  local found=0
  for dir in "$MEX_BACKUP_DIR"/*; do
    [[ -d "$dir" ]] || continue
    [[ -f "$dir/config.json" ]] || continue
    found=1
    base="$(basename "$dir")"
    printf '%s\n' "$base"
  done
  if (( found == 0 )); then
    return 1
  fi
}

mex_backup_restore() {
  local dir="$1"
  [[ -d "$dir" ]] || {
    mex_fail "Каталог резервной копии не найден: ${dir}" || true
    return 1
  }
  [[ -f "$dir/config.json" ]] || {
    mex_fail "В резервной копии нет config.json установщика." || true
    return 1
  }
  if ! mex_config_validate_file "$dir/config.json"; then
    mex_fail "Сохранённый config.json не прошёл проверку. Восстановление остановлено." || true
    return 1
  fi
  mex_backup_create "before-restore" || return 1
  mex_ensure_dirs
  cp -a "$dir/config.json" "${MEX_CONFIG_FILE}.restore"
  chmod 600 "${MEX_CONFIG_FILE}.restore" 2>/dev/null || true
  mv -f "${MEX_CONFIG_FILE}.restore" "$MEX_CONFIG_FILE"
  mex_info "Конфигурация взята из ${dir}/config.json. Правила Multi-Exit Relay будут собраны заново. Чужой файрвол целиком не восстанавливается."
  mex_iptables_apply_config || return 1
  mex_netfilter_save || true
}
