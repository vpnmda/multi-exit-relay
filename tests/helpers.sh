#!/usr/bin/env bash
# Общие проверки для тестов Multi-Exit Relay.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf '%s\n' "Этот файл подключают через source." >&2
  exit 1
fi

MEX_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_eq() {
  local got="$1" exp="$2" msg="$3"
  if [[ "$got" != "$exp" ]]; then
    fail "${msg}: получено '${got}', ожидалось '${exp}'"
  fi
}

assert_ok() {
  if ! "$@"; then
    fail "команда завершилась с ошибкой: $*"
  fi
}

assert_fail() {
  if "$@"; then
    fail "ожидалась ошибка: $*"
  fi
}

setup_dry_env() {
  local tmp ss
  tmp="$(mktemp -d)"
  export MEX_TEST_TMP="$tmp"
  export MEX_CONFIG_DIR="${tmp}/cfg"
  export MEX_CONFIG_FILE="${MEX_CONFIG_DIR}/config.json"
  export MEX_STATE_FILE="${MEX_CONFIG_DIR}/state.json"
  export MEX_BACKUP_DIR="${MEX_CONFIG_DIR}/backups"
  export MEX_LOG_FILE="${MEX_CONFIG_DIR}/logs/relay.log"
  export MEX_LOCK_FILE="${tmp}/lock"
  export MEX_SYSCTL_FILE="${tmp}/99-multi-exit-relay.conf"
  export MEX_SYSTEMD_UNIT="${tmp}/multi-exit-relay.service"
  export MEX_INSTALL_DIR="${tmp}/opt"
  export MEX_BIN_DIR="${tmp}/bin"
  export MEX_DRY_RUN=1
  export MEX_DRY_RUN_LOG="${tmp}/iptables.log"
  export MEX_SIM_DIR="${tmp}/sim"
  export MEX_SKIP_DEPS=1
  export MEX_SKIP_ROOT=1
  export MEX_SKIP_SYSTEMD=1
  export MEX_SKIP_CLI=1
  export MEX_SKIP_HOST_INTEGRATION=1
  export MEX_SKIP_NETFILTER_SAVE=1
  export MEX_SKIP_OS_CHECK=1
  export MEX_SKIP_LOCK=1
  export MEX_ASSUME_ROUTE=1
  export MEX_QUIET=1
  export MEX_PUBLIC_IP="198.51.100.5"
  export MEX_EGRESS_IFACE="eth0"
  export MEX_SOURCE_DIR="$MEX_REPO_ROOT"
  export MEX_TCP_STUB_FILE="${tmp}/tcp.stub"
  export MEX_SS_DATA="${tmp}/ss.data"
  ss="${tmp}/ss"
  cat >"$ss" <<'EOF'
#!/usr/bin/env bash
proto="tcp"
for arg in "$@"; do
  case "$arg" in
    *u*) proto="udp" ;;
  esac
done
if [[ "$proto" == "udp" ]]; then
  if [[ -n "${MEX_SS_UDP_DATA:-}" && -f "${MEX_SS_UDP_DATA}" ]]; then
    cat "${MEX_SS_UDP_DATA}"
  fi
else
  if [[ -n "${MEX_SS_DATA:-}" && -f "${MEX_SS_DATA}" ]]; then
    cat "${MEX_SS_DATA}"
  fi
fi
exit 0
EOF
  chmod 755 "$ss"
  export MEX_SS_BIN="$ss"
  export MEX_SS_UDP_DATA="${tmp}/ss-udp.data"
  mkdir -p "$MEX_CONFIG_DIR" "$MEX_BIN_DIR" "$MEX_INSTALL_DIR" "$MEX_SIM_DIR"
  : >"$MEX_DRY_RUN_LOG"
  : >"$MEX_SS_DATA"
  : >"$MEX_SS_UDP_DATA"
  local i
  : >"$MEX_TCP_STUB_FILE"
  for i in $(seq 1 30); do
    printf '%s\n' "203.0.113.${i}:443 ok" "203.0.113.${i}:8443 ok" "203.0.113.${i}:* ok" >>"$MEX_TCP_STUB_FILE"
  done
  printf '%s\n' "198.51.100.9:443 fail" "198.51.100.9:8443 fail" >>"$MEX_TCP_STUB_FILE"
  printf '%s\n' "198.51.100.8:443 ok" "198.51.100.8:8443 fail" >>"$MEX_TCP_STUB_FILE"
}

load_libs() {
  # shellcheck source=../lib/common.sh
  source "${MEX_REPO_ROOT}/lib/common.sh"
  # shellcheck source=../lib/validation.sh
  source "${MEX_REPO_ROOT}/lib/validation.sh"
  # shellcheck source=../lib/ports.sh
  source "${MEX_REPO_ROOT}/lib/ports.sh"
  # shellcheck source=../lib/iptables.sh
  source "${MEX_REPO_ROOT}/lib/iptables.sh"
  # shellcheck source=../lib/backup.sh
  source "${MEX_REPO_ROOT}/lib/backup.sh"
  # shellcheck source=../lib/exits.sh
  source "${MEX_REPO_ROOT}/lib/exits.sh"
  # shellcheck source=../lib/diagnostics.sh
  source "${MEX_REPO_ROOT}/lib/diagnostics.sh"
  mex_init
  MEX_LOCK_HELD=1
}

count_rules() {
  local table="$1" chain="$2"
  mex_iptables -t "$table" -S "$chain" 2>/dev/null | awk '/^-A /{c++} END{print c+0}'
}

rule_text() {
  local table="$1" chain="$2"
  mex_iptables -t "$table" -S "$chain" 2>/dev/null || true
}
