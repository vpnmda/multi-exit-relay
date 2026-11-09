#!/usr/bin/env bash
# Удаление только объектов Multi-Exit Relay. Чужой файрвол не очищается.
set -Eeuo pipefail

_mex_source="${BASH_SOURCE[0]}"
while [[ -L "$_mex_source" ]]; do
  _mex_link_dir="$(cd -P "$(dirname "$_mex_source")" && pwd)"
  _mex_source="$(readlink "$_mex_source")"
  [[ "$_mex_source" != /* ]] && _mex_source="${_mex_link_dir}/${_mex_source}"
done
_mex_dir="$(cd -P "$(dirname "$_mex_source")" && pwd)"
export MEX_SOURCE_DIR="$_mex_dir"

# shellcheck source=lib/common.sh
source "${_mex_dir}/lib/common.sh"
# shellcheck source=lib/validation.sh
source "${_mex_dir}/lib/validation.sh"
# shellcheck source=lib/ports.sh
source "${_mex_dir}/lib/ports.sh"
# shellcheck source=lib/iptables.sh
source "${_mex_dir}/lib/iptables.sh"
# shellcheck source=lib/backup.sh
source "${_mex_dir}/lib/backup.sh"
# shellcheck source=lib/exits.sh
source "${_mex_dir}/lib/exits.sh"
# shellcheck source=lib/diagnostics.sh
source "${_mex_dir}/lib/diagnostics.sh"

mex_init
trap 'mex_on_err $LINENO $?' ERR

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Удаление Multi-Exit Relay.

  sudo bash uninstall.sh [--yes] [--purge-config]

Удаляются только свои правила, цепочки MEX_*, свой файл sysctl,
служба и ссылки команд. Чужие правила NAT и файрвола не изменяются.
config.json удаляется только после подтверждения или с --purge-config.
Резервные копии сохраняются.
EOF
  exit 0
fi

if [[ "$(id -u)" -ne 0 && "${MEX_SKIP_ROOT:-0}" != "1" && "${MEX_DRY_RUN:-0}" != "1" ]]; then
  printf '%s\n' "Ошибка: удаление нужно запускать от root." >&2
  exit 1
fi

mex_parse_common_flags "$@" || exit 1

mex_warn "Будут удалены только правила, цепочки, sysctl-файл, служба и команды Multi-Exit Relay. Чужие правила не изменятся."
if ! mex_confirm "Удалить установку Multi-Exit Relay?"; then
  mex_info "Удаление отменено."
  exit 1
fi
mex_uninstall_system || exit 1
if mex_confirm_config_delete; then
  mex_uninstall_config_files
else
  mex_info "Конфигурация сохранена в ${MEX_CONFIG_DIR}. Резервные копии: ${MEX_BACKUP_DIR}."
fi
