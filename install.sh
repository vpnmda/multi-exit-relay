#!/usr/bin/env bash
# Multi-Exit Relay — интерактивная установка TCP-проброса на Relay.
# Можно запустить из клона репозитория или через:
#   bash <(curl -fsSL https://raw.githubusercontent.com/vpnmda/multi-exit-relay/main/install.sh)
# Перед запуском удалённого скрипта просмотрите его код.
set -Eeuo pipefail

_mex_source="${BASH_SOURCE[0]}"
while [[ -L "$_mex_source" ]]; do
  _mex_link_dir="$(cd -P "$(dirname "$_mex_source")" && pwd)"
  _mex_source="$(readlink "$_mex_source")"
  [[ "$_mex_source" != /* ]] && _mex_source="${_mex_link_dir}/${_mex_source}"
done
if _mex_dir="$(cd -P "$(dirname "$_mex_source")" 2>/dev/null && pwd)"; then
  :
else
  _mex_dir=""
fi

mex_print_help() {
  cat <<'EOF'
Multi-Exit Relay — установщик проброса TCP и UDP с Relay на Exit-серверы.

Запуск:
  sudo bash install.sh
  sudo bash install.sh --non-interactive

--non-interactive ставит зависимости, команду relay, sysctl, службу и таймер
резолва имён. Вопросы не задаются. Повторный запуск ничего не дублирует.
Если config.json уже есть и в нём есть пробросы, правила применяются сразу.

Меню:
  1  Установить новый Relay
  2  Добавить Exit
  3  Удалить Exit
  4  Показать конфигурацию
  5  Проверить соединения
  6  Проверить NAT и файрвол
  7  Сохранить конфигурацию
  8  Восстановить конфигурацию
  9  Удалить установку
  10 Выход
  11 Изменить IP Exit (порты сохраняются)

Если рядом со скриптом нет каталога lib/, установщик клонирует
репозиторий в /opt/multi-exit-relay и запускает его оттуда.
Это нужно для команды:
  bash <(curl -fsSL https://raw.githubusercontent.com/vpnmda/multi-exit-relay/main/install.sh)

Не запускайте скачанный из сети скрипт, не просмотрев его.
Более безопасный путь: git clone, чтение install.sh, затем sudo bash install.sh.
EOF
}

MEX_NONINTERACTIVE=0
for _mex_arg in "$@"; do
  case "$_mex_arg" in
    -h|--help)
      mex_print_help
      exit 0
      ;;
    --version)
      if [[ -f "${_mex_dir}/lib/common.sh" ]]; then
        _mex_ver="$(sed -n 's/^MEX_VERSION="\([^"]*\)".*/\1/p' "${_mex_dir}/lib/common.sh" | head -n 1)"
      fi
      printf '%s\n' "multi-exit-relay ${_mex_ver:-2.0.0}"
      exit 0
      ;;
    --non-interactive|--noninteractive)
      MEX_NONINTERACTIVE=1
      ;;
    --)
      ;;
    -*)
      printf '%s\n' "Ошибка: неизвестный аргумент: ${_mex_arg}" >&2
      exit 1
      ;;
  esac
done
unset _mex_arg _mex_ver

if [[ "$(id -u)" -ne 0 && "${MEX_SKIP_ROOT:-0}" != "1" ]]; then
  printf '%s\n' "Ошибка: запустите установщик от root (sudo bash install.sh)." >&2
  exit 1
fi

if [[ ! -f "${_mex_dir}/lib/common.sh" ]]; then
  _mex_dest="${MEX_INSTALL_DIR:-/opt/multi-exit-relay}"
  printf '%s\n' "Рядом со скриптом нет каталога lib/. Загрузка репозитория в ${_mex_dest}." >&2
  mkdir -p "$(dirname "$_mex_dest")"
  if [[ -f "${_mex_dest}/lib/common.sh" ]]; then
    exec bash "${_mex_dest}/install.sh" "$@"
  fi
  if [[ -d "$_mex_dest" ]] && [[ -n "$(ls -A "$_mex_dest" 2>/dev/null || true)" ]]; then
    printf '%s\n' "Ошибка: ${_mex_dest} уже существует и не содержит установщик. Укажите другой путь в MEX_INSTALL_DIR." >&2
    exit 1
  fi
  if command -v git >/dev/null 2>&1; then
    git clone --depth 1 https://github.com/vpnmda/multi-exit-relay.git "$_mex_dest"
  elif command -v curl >/dev/null 2>&1; then
    _mex_tmp="$(mktemp -d)"
    curl -fsSL --retry 3 --max-time 60 -o "${_mex_tmp}/src.tar.gz" \
      https://github.com/vpnmda/multi-exit-relay/archive/refs/heads/main.tar.gz
    tar -xzf "${_mex_tmp}/src.tar.gz" -C "$_mex_tmp"
    mv "${_mex_tmp}/multi-exit-relay-main" "$_mex_dest"
    rm -rf "$_mex_tmp"
  else
    printf '%s\n' "Ошибка: нужны git или curl, чтобы скачать репозиторий." >&2
    exit 1
  fi
  exec bash "${_mex_dest}/install.sh" "$@"
fi

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

mex_menu() {
  local choice
  while true; do
    cat <<'EOF'

==============================================
 Multi-Exit Relay — проброс TCP и UDP на Exit
==============================================
 1) Установить новый Relay
 2) Добавить Exit
 3) Удалить Exit
 4) Показать конфигурацию
 5) Проверить соединения
 6) Проверить NAT и файрвол
 7) Сохранить конфигурацию
 8) Восстановить конфигурацию
 9) Удалить установку
10) Выход
11) Изменить IP Exit (порты сохраняются)

EOF
    if ! mex_prompt choice "Выберите пункт: "; then
      printf '\n%s\n' "Выход."
      return 0
    fi
    case "$choice" in
      1)
        mex_wizard_install || true
        ;;
      2)
        mex_wizard_add_one || true
        ;;
      3)
        mex_wizard_remove || true
        ;;
      4)
        mex_exit_print_table || true
        ;;
      5)
        mex_diag_connections || true
        ;;
      6)
        mex_diag_nat || true
        ;;
      7)
        mex_backup_create "manual" || true
        ;;
      8)
        mex_wizard_restore || true
        ;;
      9)
        mex_warn "Будут удалены только правила, цепочки, sysctl-файл, служба и команды Multi-Exit Relay."
        if mex_confirm "Удалить установку Multi-Exit Relay?"; then
          mex_uninstall_system || true
          if mex_confirm_config_delete; then
            mex_uninstall_config_files || true
          else
            mex_info "Конфигурация сохранена: ${MEX_CONFIG_DIR}"
          fi
        else
          mex_info "Удаление отменено."
        fi
        ;;
      10|0|q|Q|выход|Выход)
        printf '%s\n' "Выход."
        return 0
        ;;
      11)
        mex_wizard_change_ip || true
        ;;
      *)
        mex_warn "Нет пункта «${choice}». Введите номер от 1 до 11."
        ;;
    esac
  done
}

if [[ "$MEX_NONINTERACTIVE" == "1" ]]; then
  _mex_rc=0
  mex_install_noninteractive || _mex_rc=$?
  exit "$_mex_rc"
fi

if [[ ! -t 0 ]]; then
  printf '%s\n' "Ошибка: интерактивное меню требует терминал. Для автоматизации: sudo bash install.sh --non-interactive, затем relay apply и relay check --json." >&2
  exit 1
fi

mex_menu
