#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=helpers.sh
source "$(dirname "$0")/helpers.sh"
setup_dry_env
load_libs

seed_foreign() {
  mex_iptables -P FORWARD DROP
  mex_iptables -A INPUT -p tcp --dport 22 -m comment --comment foreign-ssh -j ACCEPT
  mex_iptables -t nat -A PREROUTING -p tcp --dport 9 -m comment --comment foreign-dnat -j DNAT --to-destination 198.51.100.9:9
  mex_iptables -t nat -A POSTROUTING -s 10.9.9.0/24 -m comment --comment foreign-masq -j MASQUERADE
}

assert_foreign_intact() {
  local policy
  policy="$(mex_diag_forward_policy)"
  assert_eq "$policy" "DROP" "политика FORWARD"
  rule_text filter INPUT | grep -q 'foreign-ssh' || fail "пропало чужое правило SSH"
  rule_text nat PREROUTING | grep -q 'foreign-dnat' || fail "пропал чужой DNAT"
  rule_text nat POSTROUTING | grep -q 'foreign-masq' || fail "пропала чужая MASQUERADE"
}

assert_exit_rules() {
  local id="$1"
  mex_iptables_has_comment nat MEX_PREROUTING "mex:${id}" || fail "нет DNAT ${id}"
  mex_iptables_has_comment nat MEX_POSTROUTING "mex:${id}" || fail "нет MASQUERADE ${id}"
  mex_iptables_has_comment filter MEX_FORWARD "mex:${id}" || fail "нет FORWARD ${id}"
  local dnat masq fwd
  dnat="$(mex_iptables_list nat MEX_PREROUTING | grep -c -F "/* mex:${id} */" || true)"
  masq="$(mex_iptables_list nat MEX_POSTROUTING | grep -c -F "/* mex:${id} */" || true)"
  fwd="$(mex_iptables_list filter MEX_FORWARD | grep -c -F "/* mex:${id} */" || true)"
  assert_eq "$dnat" 2 "DNAT ${id}"
  assert_eq "$masq" 2 "MASQUERADE ${id}"
  assert_eq "$fwd" 6 "FORWARD ${id}"
}

assert_no_global_masq() {
  local line
  while IFS= read -r line; do
    [[ "$line" == *MASQUERADE* ]] || continue
    [[ "$line" == *foreign-masq* ]] && continue
    [[ "$line" == *"-d "* ]] || fail "MASQUERADE без адреса назначения: ${line}"
    [[ "$line" == *"--dport "* ]] || fail "MASQUERADE без порта: ${line}"
    [[ "$line" == *"-p tcp"* || "$line" == *"-p udp"* ]] || fail "MASQUERADE без tcp/udp: ${line}"
  done < <(mex_iptables -t nat -S 2>/dev/null || true)
}

seed_foreign
: >"$MEX_DRY_RUN_LOG"

assert_ok mex_exit_add "Германия" "203.0.113.10"
assert_eq "$(jq -r '.exits[0].host' "$MEX_CONFIG_FILE")" "203.0.113.10" "host первого Exit"
assert_eq "$(jq -c '.exits[0].forwards' "$MEX_CONFIG_FILE")" '[{"proto":"tcp","listen":443,"target":443},{"proto":"tcp","listen":8443,"target":8443}]' "пробросы первого Exit"
assert_exit_rules exit-1
assert_foreign_intact
assert_no_global_masq
mex_iptables_has_comment mangle FORWARD "mex:tcpmss" || fail "нет TCPMSS"
assert_eq "$(count_rules mangle FORWARD)" "1" "TCPMSS один раз"
grep -q 'net.ipv4.ip_forward=1' "$MEX_SYSCTL_FILE" || fail "sysctl не записан"

if mex_exit_add "Ещё" "203.0.113.10"; then
  fail "дубликат IP должен быть отклонён"
fi
assert_eq "$(jq -r '.exits | length' "$MEX_CONFIG_FILE")" "1" "после дубликата один Exit"

: >"$MEX_DRY_RUN_LOG"
assert_ok mex_iptables_apply_config
if grep -Eq '(^| )-A( |$)' "$MEX_DRY_RUN_LOG"; then
  fail "повторное применение добавило правила: $(grep -E '(^| )-A( |$)' "$MEX_DRY_RUN_LOG" | head)"
fi
assert_eq "$(count_rules nat MEX_PREROUTING)" "2" "идемпотентность DNAT"
assert_eq "$(count_rules filter MEX_FORWARD)" "7" "идемпотентность FORWARD"

before="$(jq -c '.exits[0].forwards' "$MEX_CONFIG_FILE")"
assert_ok mex_exit_add "Нидерланды" "203.0.113.11"
after="$(jq -c '.exits[0].forwards' "$MEX_CONFIG_FILE")"
assert_eq "$after" "$before" "порты первого Exit не изменились"
assert_eq "$(jq -r '.exits[1].forwards[0].listen' "$MEX_CONFIG_FILE")" "10443" "второй Exit порт 1"
assert_eq "$(jq -r '.exits[1].forwards[1].listen' "$MEX_CONFIG_FILE")" "18443" "второй Exit порт 2"
assert_exit_rules exit-1
assert_exit_rules exit-2

assert_ok mex_exit_add "Финляндия" "203.0.113.12"
assert_ok mex_exit_add "Швеция" "203.0.113.13"
assert_ok mex_exit_add "Польша" "203.0.113.14"
assert_ok mex_exit_add "Франция" "203.0.113.15"
assert_eq "$(jq -r '.exits | length' "$MEX_CONFIG_FILE")" "6" "шесть Exit"
expected=$'443\t8443\n10443\t18443\n20443\t28443\n30443\t38443\n40443\t48443\n50443\t58443'
got="$(jq -r '.exits[] | [.forwards[] | select(.proto=="tcp").listen] | @tsv' "$MEX_CONFIG_FILE")"
assert_eq "$got" "$expected" "таблица портов шести Exit"
for id in exit-1 exit-2 exit-3 exit-4 exit-5 exit-6; do
  assert_exit_rules "$id"
done
assert_eq "$(count_rules mangle FORWARD)" "1" "TCPMSS не дублируется на шести Exit"

assert_ok mex_exit_add "Седьмой" "203.0.113.16"
assert_eq "$(jq -r '.exits[6].forwards[0].listen' "$MEX_CONFIG_FILE")" "11443" "седьмой порт 1"
assert_eq "$(jq -r '.exits[6].forwards[1].listen' "$MEX_CONFIG_FILE")" "19443" "седьмой порт 2"
(( $(jq -r '.exits[6].forwards[1].listen' "$MEX_CONFIG_FILE") <= 65535 )) || fail "порт вне диапазона"

assert_ok mex_exit_remove exit-3
assert_eq "$(jq -r '.exits | length' "$MEX_CONFIG_FILE")" "6" "после удаления осталось шесть"
if mex_iptables_has_comment nat MEX_PREROUTING "mex:exit-3"; then
  fail "правила exit-3 остались"
fi
for id in exit-1 exit-2 exit-4 exit-5 exit-6 exit-7; do
  assert_exit_rules "$id"
done
assert_eq "$(jq -r '.exits[] | select(.id=="exit-1") | .forwards[0].listen' "$MEX_CONFIG_FILE")" "443" "порт exit-1 после удаления"
assert_foreign_intact

ports_before="$(jq -r '.exits[] | select(.id=="exit-2") | [.forwards[].listen] | join(" ")' "$MEX_CONFIG_FILE")"
assert_ok mex_exit_change_ip exit-2 203.0.113.30
ports_after="$(jq -r '.exits[] | select(.id=="exit-2") | [.forwards[].listen] | join(" ")' "$MEX_CONFIG_FILE")"
assert_eq "$ports_after" "$ports_before" "смена IP сохраняет порты"
assert_eq "$(jq -r '.exits[] | select(.id=="exit-2") | .host' "$MEX_CONFIG_FILE")" "203.0.113.30" "новый IP"
rule_text nat MEX_PREROUTING | grep -q '203.0.113.30:443' || fail "DNAT не указывает на новый IP"
if rule_text nat MEX_PREROUTING | grep -q '203.0.113.11:443'; then
  fail "старый IP остался в DNAT"
fi

saved="$MEX_LAST_BACKUP"
cp -a "$MEX_CONFIG_FILE" "${MEX_TEST_TMP}/live.json"
mex_iptables_uninstall
if mex_iptables_chain_exists nat MEX_PREROUTING; then
  fail "цепочка осталась после очистки"
fi
cp -a "${MEX_TEST_TMP}/live.json" "$MEX_CONFIG_FILE"
assert_ok mex_iptables_apply_config
assert_exit_rules exit-1
assert_exit_rules exit-2
assert_foreign_intact
assert_eq "$(count_rules mangle FORWARD)" "1" "TCPMSS восстановлен один раз"

assert_ok mex_backup_restore "$saved"
assert_foreign_intact
jq -e '.exits | length > 0' "$MEX_CONFIG_FILE" >/dev/null || fail "восстановление не вернуло Exit"

if MEX_PUBLIC_IP="203.0.113.10" mex_exit_add "Сам" "203.0.113.10"; then
  :
fi
# Публичный IP в файле уже 198.51.100.5, отдельная проверка самоадреса:
tmp_cfg="$(mktemp)"
jq '.public_ip = "203.0.113.40"' "$MEX_CONFIG_FILE" >"$tmp_cfg"
cp "$tmp_cfg" "$MEX_CONFIG_FILE"
if mex_exit_add "Сам" "203.0.113.40"; then
  fail "IP Relay нельзя добавить как Exit"
fi

err="$(mex_exit_add "Плохой" "198.51.100.9" 2>&1 >/dev/null || true)"
printf '%s\n' "$err" | grep -q "только проверка доступности TCP-порта" || fail "нет формулировки TCP-проверки: ${err}"
printf '%s\n' "$err" | grep -q "не проверка REALITY" || fail "нет уточнения, что это не REALITY: ${err}"
if jq -e '.exits[] | select(.host=="198.51.100.9")' "$MEX_CONFIG_FILE" >/dev/null; then
  fail "недоступный Exit был добавлен"
fi
assert_ok mex_exit_add "Принудительный" "198.51.100.9" "" "" 1
assert_eq "$(jq -r '.exits[] | select(.host=="198.51.100.9") | .status' "$MEX_CONFIG_FILE")" "active-forced" "статус force"

if mex_exit_add "Ручной" "203.0.113.21" 25000 26000; then
  :
else
  fail "ручные свободные порты должны приниматься"
fi
assert_eq "$(jq -r '.exits[] | select(.host=="203.0.113.21") | [.forwards[].listen] | join(" ")' "$MEX_CONFIG_FILE")" "25000 26000" "ручные порты"
if mex_exit_add "Занятый" "203.0.113.22" 25000 27000; then
  fail "занятый ручной порт нельзя перезаписать"
fi
if mex_exit_add "SSH" "203.0.113.23" 22 2222; then
  fail "порт 22 нельзя назначать"
fi

check_out="$(mex_diag_check || true)"
printf '%s\n' "$check_out" | grep -q "ip_forward: 1" || fail "check не показал ip_forward"
printf '%s\n' "$check_out" | grep -q "TCPMSS: присутствует" || fail "check не показал TCPMSS"
printf '%s\n' "$check_out" | grep -q "Это не проверка REALITY" || fail "check не предупредил про REALITY"
printf '%s\n' "$check_out" | grep -q $'Германия' || fail "check не показал Exit"

assert_ok mex_uninstall_system
assert_foreign_intact
if mex_iptables_chain_exists nat MEX_PREROUTING \
  || mex_iptables_chain_exists nat MEX_POSTROUTING \
  || mex_iptables_chain_exists filter MEX_FORWARD; then
  fail "собственные цепочки остались после удаления"
fi
if mex_iptables_has_comment mangle FORWARD "mex:tcpmss"; then
  fail "TCPMSS остался после удаления"
fi
if rule_text filter INPUT | grep -q 'mex:'; then
  fail "в INPUT остались наши комментарии"
fi
[[ -d "$MEX_BACKUP_DIR" ]] || fail "резервные копии удалены"
find "$MEX_BACKUP_DIR" -mindepth 1 -type d | grep -q . || fail "нет каталогов резервных копий"
[[ -f "$MEX_CONFIG_FILE" ]] || fail "config.json удалён без подтверждения"
assert_ok mex_uninstall_config_files
[[ ! -f "$MEX_CONFIG_FILE" ]] || fail "config.json не удалён по запросу"
[[ -d "$MEX_BACKUP_DIR" ]] || fail "после удаления конфигурации пропали копии"

if grep -E 'udp|--dport 22' "$MEX_DRY_RUN_LOG" | grep -v foreign-ssh >/dev/null; then
  :
fi
if grep -q -- '-p udp' "$MEX_DRY_RUN_LOG"; then
  fail "в журнале есть UDP"
fi

printf '%s\n' "OK rules"
