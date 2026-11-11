#!/usr/bin/env bash
# Общие функции Multi-Exit Relay: журнал, блокировка, пути, подтверждения.
# Файл подключается через source, сам по себе не запускается.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source, а не запускают напрямую." >&2
  exit 1
fi

[[ -n "${MEX_COMMON_LOADED:-}" ]] && return 0
MEX_COMMON_LOADED=1

# Используется relay и сообщениями установщика.
# shellcheck disable=SC2034
MEX_VERSION="2.0.0"

mex_init() {
  MEX_CONFIG_DIR="${MEX_CONFIG_DIR:-/etc/multi-exit-relay}"
  MEX_CONFIG_FILE="${MEX_CONFIG_FILE:-$MEX_CONFIG_DIR/config.json}"
  MEX_STATE_FILE="${MEX_STATE_FILE:-$MEX_CONFIG_DIR/state.json}"
  MEX_BACKUP_DIR="${MEX_BACKUP_DIR:-$MEX_CONFIG_DIR/backups}"
  MEX_LOG_FILE="${MEX_LOG_FILE:-$MEX_CONFIG_DIR/logs/relay.log}"
  MEX_INSTALL_DIR="${MEX_INSTALL_DIR:-/opt/multi-exit-relay}"
  MEX_BIN_DIR="${MEX_BIN_DIR:-/usr/local/bin}"
  MEX_LOCK_FILE="${MEX_LOCK_FILE:-/var/lock/multi-exit-relay.lock}"
  MEX_SYSCTL_FILE="${MEX_SYSCTL_FILE:-/etc/sysctl.d/99-multi-exit-relay.conf}"
  MEX_SYSTEMD_UNIT="${MEX_SYSTEMD_UNIT:-/etc/systemd/system/multi-exit-relay.service}"
  MEX_IPTABLES="${MEX_IPTABLES:-iptables}"
  MEX_IP6TABLES="${MEX_IP6TABLES:-ip6tables}"
  MEX_IPTABLES_SAVE="${MEX_IPTABLES_SAVE:-iptables-save}"
  MEX_IP6TABLES_SAVE="${MEX_IP6TABLES_SAVE:-ip6tables-save}"
  MEX_IP_BIN="${MEX_IP_BIN:-ip}"
  MEX_SS_BIN="${MEX_SS_BIN:-ss}"
  MEX_SYSCTL_BIN="${MEX_SYSCTL_BIN:-sysctl}"
  MEX_SOURCE_DIR="${MEX_SOURCE_DIR:-}"
  MEX_DRY_RUN="${MEX_DRY_RUN:-0}"
  MEX_SKIP_ROOT="${MEX_SKIP_ROOT:-0}"
  MEX_SKIP_DEPS="${MEX_SKIP_DEPS:-0}"
  MEX_SKIP_SYSTEMD="${MEX_SKIP_SYSTEMD:-0}"
  MEX_SKIP_CLI="${MEX_SKIP_CLI:-0}"
  MEX_SKIP_HOST_INTEGRATION="${MEX_SKIP_HOST_INTEGRATION:-0}"
  MEX_SKIP_NETFILTER_SAVE="${MEX_SKIP_NETFILTER_SAVE:-0}"
  MEX_SKIP_OS_CHECK="${MEX_SKIP_OS_CHECK:-0}"
  MEX_SKIP_LOCK="${MEX_SKIP_LOCK:-0}"
  MEX_ASSUME_YES="${MEX_ASSUME_YES:-0}"
  MEX_ASSUME_ROUTE="${MEX_ASSUME_ROUTE:-0}"
  MEX_QUIET="${MEX_QUIET:-0}"
  MEX_JSON="${MEX_JSON:-0}"
  MEX_INFO_STDERR="${MEX_INFO_STDERR:-0}"
  MEX_JSON_COMMAND="${MEX_JSON_COMMAND:-}"
  MEX_LOCK_WAIT="${MEX_LOCK_WAIT:-60}"
  MEX_RESOLVE_TIMEOUT="${MEX_RESOLVE_TIMEOUT:-5}"
  if [[ "$MEX_DRY_RUN" == "1" && -z "${MEX_SIM_DIR:-}" ]]; then
    MEX_SIM_DIR="${MEX_CONFIG_DIR}/sim"
  fi
  # shellcheck disable=SC2178
  # shellcheck disable=SC2034
  declare -gA MEX_PORT_OCCUPIED=()
}

mex_log() {
  local level="$1"
  shift
  local msg="$*"
  local ts dir
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf '%s' "unknown-time")"
  if [[ -n "${MEX_LOG_FILE:-}" ]]; then
    dir="$(dirname "$MEX_LOG_FILE")"
    mkdir -p "$dir" 2>/dev/null || true
    printf '%s [%s] %s\n' "$ts" "$level" "$msg" >>"$MEX_LOG_FILE" 2>/dev/null || true
  fi
}

mex_info() {
  mex_log INFO "$*"
  if [[ "${MEX_QUIET:-0}" == "1" ]]; then
    return 0
  fi
  # JSON-команды и relay apply держат stdout чистым: журнал идёт в stderr.
  if [[ "${MEX_JSON:-0}" == "1" || "${MEX_INFO_STDERR:-0}" == "1" ]]; then
    printf '%s\n' "$*" >&2
    return 0
  fi
  printf '%s\n' "$*"
}

mex_warn() {
  mex_log WARN "$*"
  if [[ "${MEX_QUIET:-0}" != "1" ]]; then
    printf 'Предупреждение: %s\n' "$*" >&2
  fi
}

mex_fail() {
  mex_log ERROR "$*"
  printf 'Ошибка: %s\n' "$*" >&2
  return 1
}

mex_on_err() {
  local line="$1"
  local rc="${2:-1}"
  mex_log ERROR "Непредвиденный сбой на строке ${line}, код ${rc}, команда: ${BASH_COMMAND}"
  printf 'Ошибка: непредвиденный сбой на строке %s (код %s).\n' "$line" "$rc" >&2
  if [[ -n "${MEX_LOG_FILE:-}" ]]; then
    printf 'Подробности: %s\n' "$MEX_LOG_FILE" >&2
  fi
  exit "$rc"
}

mex_require_root() {
  if [[ "${MEX_SKIP_ROOT:-0}" == "1" || "${MEX_DRY_RUN:-0}" == "1" ]]; then
    return 0
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    mex_fail "Нужны права root. Запустите команду через sudo." || true
    return 1
  fi
}

mex_acquire_lock() {
  if [[ "${MEX_SKIP_LOCK:-0}" == "1" ]]; then
    return 0
  fi
  if [[ -n "${MEX_LOCK_HELD:-}" ]]; then
    return 0
  fi
  local lock dir
  lock="${MEX_LOCK_FILE:-/var/lock/multi-exit-relay.lock}"
  dir="$(dirname "$lock")"
  mkdir -p "$dir" 2>/dev/null || {
    mex_fail "Не удалось создать каталог блокировки ${dir}." || true
    return 1
  }
  exec 9>"$lock" || {
    mex_fail "Не удалось открыть файл блокировки ${lock}." || true
    return 1
  }
  if ! flock -w "${MEX_LOCK_WAIT:-60}" 9; then
    mex_fail "Уже выполняется другой экземпляр Multi-Exit Relay." || true
    return 5
  fi
  MEX_LOCK_HELD=1
}

mex_confirm() {
  local prompt="$1"
  local answer
  if [[ "${MEX_ASSUME_YES:-0}" == "1" ]]; then
    mex_log INFO "Автоподтверждение: ${prompt}"
    return 0
  fi
  if [[ ! -t 0 ]]; then
    mex_fail "Нужно подтверждение («${prompt}»), но стандартный ввод не терминал. Добавьте --yes." || true
    return 1
  fi
  if ! read -r -p "${prompt} [y/N] " answer; then
    return 1
  fi
  case "$answer" in
    y|Y|yes|YES|д|Д|да|Да|ДА) return 0 ;;
    *) return 1 ;;
  esac
}

# Удаление конфигурации не подчиняется --yes: нужен отдельный --purge-config или ответ в терминале.
mex_confirm_config_delete() {
  local saved rc
  if [[ "${MEX_OPT_PURGE_CONFIG:-0}" == "1" ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    mex_info "config.json сохранён. Чтобы удалить его без вопроса, добавьте --purge-config. Резервные копии остаются."
    return 1
  fi
  saved="${MEX_ASSUME_YES:-0}"
  MEX_ASSUME_YES=0
  mex_confirm "Удалить config.json и state.json? Резервные копии сохранятся."
  rc=$?
  MEX_ASSUME_YES="$saved"
  return "$rc"
}

mex_confirm_default_yes() {
  local prompt="$1"
  local answer
  if [[ ! -t 0 ]]; then
    return 1
  fi
  if ! read -r -p "${prompt} [Y/n] " answer; then
    return 1
  fi
  case "$answer" in
    ""|y|Y|yes|YES|д|Д|да|Да|ДА) return 0 ;;
    *) return 1 ;;
  esac
}

mex_prompt() {
  local __var="$1"
  local prompt="$2"
  local default="${3:-}"
  local answer
  if ! read -r -p "$prompt" answer; then
    return 1
  fi
  if [[ -z "$answer" ]]; then
    answer="$default"
  fi
  printf -v "$__var" '%s' "$answer"
}

mex_timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

mex_ensure_dirs() {
  mkdir -p "$MEX_CONFIG_DIR" "$MEX_BACKUP_DIR" "$(dirname "$MEX_LOG_FILE")"
  chmod 700 "$MEX_CONFIG_DIR" "$MEX_BACKUP_DIR" 2>/dev/null || true
}

mex_atomic_write() {
  local dest="$1"
  local tmp
  mkdir -p "$(dirname "$dest")"
  tmp="$(mktemp "${dest}.XXXXXX")"
  cat >"$tmp"
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$dest"
}

mex_have() {
  command -v "$1" >/dev/null 2>&1
}

mex_detect_os() {
  local id ver
  if [[ -n "${MEX_FAKE_OS_ID:-}" ]]; then
    printf '%s %s\n' "$MEX_FAKE_OS_ID" "${MEX_FAKE_OS_VERSION:-}"
    return 0
  fi
  if [[ ! -r /etc/os-release ]]; then
    printf '%s %s\n' "unknown" "unknown"
    return 1
  fi
  id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)"
  ver="$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2; exit}' /etc/os-release)"
  printf '%s %s\n' "${id:-unknown}" "${ver:-unknown}"
}

mex_os_is_supported() {
  local id ver
  if [[ "${MEX_SKIP_OS_CHECK:-0}" == "1" ]]; then
    return 0
  fi
  read -r id ver < <(mex_detect_os || true)
  [[ "$id" == "ubuntu" && ( "$ver" == "22.04" || "$ver" == "24.04" ) ]]
}

mex_detect_egress_iface() {
  local iface
  if [[ -n "${MEX_EGRESS_IFACE:-}" ]]; then
    printf '%s\n' "$MEX_EGRESS_IFACE"
    return 0
  fi
  iface="$("${MEX_IP_BIN}" -4 route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
  if [[ -n "$iface" ]]; then
    printf '%s\n' "$iface"
    return 0
  fi
  return 1
}

mex_detect_public_ip() {
  local url ip
  if [[ -n "${MEX_PUBLIC_IP:-}" ]]; then
    printf '%s\n' "$MEX_PUBLIC_IP"
    return 0
  fi
  if mex_have curl; then
    for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
      ip="$(curl -4 -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
      if mex_valid_ipv4 "$ip"; then
        printf '%s\n' "$ip"
        return 0
      fi
    done
  fi
  ip="$("${MEX_IP_BIN}" -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
  if mex_valid_ipv4 "$ip"; then
    printf '%s\n' "$ip"
    return 0
  fi
  return 1
}

mex_is_private_ipv4() {
  local ip="$1" o1 o2
  IFS=. read -r o1 o2 _ _ <<<"$ip"
  if (( o1 == 10 )); then
    return 0
  fi
  if (( o1 == 172 && o2 >= 16 && o2 <= 31 )); then
    return 0
  fi
  if (( o1 == 192 && o2 == 168 )); then
    return 0
  fi
  return 1
}

mex_dry_log() {
  [[ -n "${MEX_DRY_RUN_LOG:-}" ]] || return 0
  local line="" a quoted
  for a in "$@"; do
    printf -v quoted '%q' "$a"
    line+=" ${quoted}"
  done
  printf '%s\n' "${line# }" >>"$MEX_DRY_RUN_LOG" || true
}

mex_parse_common_flags() {
  # Поля читает relay/uninstall.sh после возврата из функции.
  export MEX_OPT_YES=0
  export MEX_OPT_FORCE=0
  export MEX_OPT_NAME=""
  export MEX_OPT_IP=""
  export MEX_OPT_ID=""
  export MEX_OPT_P1=""
  export MEX_OPT_P2=""
  export MEX_OPT_PURGE_CONFIG=0
  export MEX_OPT_BACKUP=""
  export MEX_OPT_JSON=0
  export MEX_OPT_CONFIG=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes|-y)
        export MEX_OPT_YES=1
        shift
        ;;
      --force)
        export MEX_OPT_FORCE=1
        shift
        ;;
      --json)
        export MEX_OPT_JSON=1
        MEX_JSON=1
        shift
        ;;
      --config)
        export MEX_OPT_CONFIG="${2:-}"
        if [[ -z "$MEX_OPT_CONFIG" ]]; then
          mex_fail "Укажите путь после --config." || true
          return 1
        fi
        shift 2
        ;;
      --name)
        export MEX_OPT_NAME="${2:-}"
        shift 2
        ;;
      --ip)
        export MEX_OPT_IP="${2:-}"
        shift 2
        ;;
      --id)
        export MEX_OPT_ID="${2:-}"
        shift 2
        ;;
      --relay-port-443)
        export MEX_OPT_P1="${2:-}"
        shift 2
        ;;
      --relay-port-8443)
        export MEX_OPT_P2="${2:-}"
        shift 2
        ;;
      --purge-config)
        export MEX_OPT_PURGE_CONFIG=1
        shift
        ;;
      --backup)
        export MEX_OPT_BACKUP="${2:-}"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      *)
        mex_fail "Неизвестный аргумент: $1" || true
        return 1
        ;;
    esac
  done
  if [[ "$MEX_OPT_YES" == "1" ]]; then
    MEX_ASSUME_YES=1
  fi
}

# Печатает стабильную JSON-ошибку на stdout, если включён MEX_JSON, текст — на stderr.
# Код возврата равен первому аргументу. Коды error стабильны, message — для человека.
mex_json_error() {
  local exit_code="$1"
  local err="$2"
  local message="$3"
  mex_log ERROR "${err}: ${message}"
  printf 'Ошибка: %s\n' "$message" >&2
  if [[ "${MEX_JSON:-0}" == "1" ]]; then
    if ! command -v jq >/dev/null 2>&1; then
      printf '%s\n' "Ошибка: для --json нужна утилита jq." >&2
      return 3
    fi
    jq -n \
      --arg command "${MEX_JSON_COMMAND:-}" \
      --arg error "$err" \
      --arg message "$message" \
      --arg version "${MEX_VERSION:-}" \
      --arg config_file "${MEX_CONFIG_FILE:-}" \
      '{
        ok: false,
        command: $command,
        error: $error,
        message: $message,
        version: $version,
        config_file: $config_file,
        problems: [{code: $error, message: $message}]
      }'
  fi
  return "$exit_code"
}
