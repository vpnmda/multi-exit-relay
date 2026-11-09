#!/usr/bin/env bash
# Контракт автоматизации: схема v2, UDP, apply, JSON, коды выхода, домен.
set -Eeuo pipefail
# shellcheck source=helpers.sh
source "$(dirname "$0")/helpers.sh"
setup_dry_env
load_libs

canon_a="$(mex_canon_from_args -p udp --dport 443 -m comment --comment mex:de-1 -j DNAT --to-destination 203.0.113.10:443)"
canon_b="$(mex_canon_from_args -p udp -m udp --dport 443 -m comment --comment '"mex:de-1"' -j DNAT --to-destination 203.0.113.10:443)"
assert_eq "$canon_a" "$canon_b" "канон DNAT совпадает с выводом iptables -S"

canon_c="$(mex_canon_from_args -p udp -d 203.0.113.10 --dport 443 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment mex:de-1 -j ACCEPT)"
canon_d="$(mex_canon_from_args -d 203.0.113.10/32 -p udp -m udp --dport 443 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment '"mex:de-1"' -j ACCEPT)"
assert_eq "$canon_c" "$canon_d" "канон ctstate не зависит от порядка флагов"

cfg="${MEX_TEST_TMP}/v2.json"
cat >"$cfg" <<'JSON'
{
  "version": 2,
  "exits": [
    {
      "id": "de-1",
      "name": "Германия",
      "host": "203.0.113.10",
      "forwards": [
        {"proto": "tcp", "listen": 443, "target": 443},
        {"proto": "tcp", "listen": 8443, "target": 8443},
        {"proto": "udp", "listen": 443, "target": 443},
        {"proto": "tcp", "listen": 4443, "target": 4443},
        {"proto": "tcp", "listen": 6443, "target": 6443}
      ]
    },
    {
      "id": "nl-1",
      "name": "Нидерланды",
      "host": "203.0.113.20",
      "forwards": [
        {"proto": "tcp", "listen": 10443, "target": 443},
        {"proto": "udp", "listen": 18443, "target": 443}
      ]
    }
  ]
}
JSON
cp -a "$cfg" "$MEX_CONFIG_FILE"
: >"$MEX_DRY_RUN_LOG"
rules_have() {
  local text
  text="$(rule_text "$1" "$2" || true)"
  [[ "$text" == *"$3"* ]] || fail "$4"
}
rules_lack() {
  local text
  text="$(rule_text "$1" "$2" || true)"
  [[ "$text" != *"$3"* ]] || fail "$4"
}

assert_ok mex_apply_from_config
rules_have nat MEX_PREROUTING "-p udp" "нет UDP DNAT"
rules_have nat MEX_PREROUTING "203.0.113.10:4443" "нет произвольного порта 4443"
rules_have nat MEX_PREROUTING "203.0.113.10:6443" "нет порта 6443"
rules_have nat MEX_POSTROUTING "-p udp" "нет UDP MASQUERADE"
rules_have filter MEX_FORWARD "-p udp" "нет UDP FORWARD"
rules_have filter MEX_FORWARD "ESTABLISHED,RELATED" "нет conntrack ESTABLISHED для UDP/TCP"
dnat_count="$(mex_iptables -t nat -S MEX_PREROUTING | awk '/^-A /{c++} END{print c+0}')"
assert_eq "$dnat_count" "7" "DNAT: 5 у de-1 и 2 у nl-1"

: >"$MEX_DRY_RUN_LOG"
assert_ok mex_apply_from_config
if grep -Eq '(^| )-A( |$)' "$MEX_DRY_RUN_LOG"; then
  fail "повторный apply добавил правила"
fi
if grep -Eq '(^| )-D( |$)' "$MEX_DRY_RUN_LOG"; then
  fail "повторный apply удалил правила"
fi
assert_eq "${MEX_RULES_ADDED}" "0" "rules_added"
assert_eq "${MEX_RULES_REMOVED}" "0" "rules_removed"

jq 'del(.exits[1])' "$MEX_CONFIG_FILE" >"${MEX_TEST_TMP}/one.json"
cp -a "${MEX_TEST_TMP}/one.json" "$MEX_CONFIG_FILE"
assert_ok mex_apply_from_config
rules_lack nat MEX_PREROUTING "mex:nl-1" "правила удалённого Exit остались"
rules_have nat MEX_PREROUTING "mex:de-1" "правила оставшегося Exit пропали"
rules_have nat MEX_PREROUTING "-p udp" "UDP оставшегося Exit пропал"

# Смена адреса: новое правило ставится до удаления старого.
cp -a "$cfg" "$MEX_CONFIG_FILE"
assert_ok mex_apply_from_config
jq '.exits[0].host = "203.0.113.30"' "$MEX_CONFIG_FILE" >"${MEX_TEST_TMP}/moved.json"
cp -a "${MEX_TEST_TMP}/moved.json" "$MEX_CONFIG_FILE"
: >"$MEX_DRY_RUN_LOG"
assert_ok mex_apply_from_config
if ! grep -q -- '-A' "$MEX_DRY_RUN_LOG" || ! grep -q -- '-D' "$MEX_DRY_RUN_LOG"; then
  fail "смена host должна и добавить, и удалить правило"
fi
# В журнале первое изменение DNAT — добавление, удаление позже.
add_line="$(grep -n -- '-A MEX_PREROUTING -p tcp --dport 443' "$MEX_DRY_RUN_LOG" | head -n 1 | cut -d: -f1)"
del_line="$(grep -n -- '-D MEX_PREROUTING' "$MEX_DRY_RUN_LOG" | head -n 1 | cut -d: -f1)"
[[ -n "$add_line" && -n "$del_line" && "$add_line" -lt "$del_line" ]] || fail "старое правило удалено раньше нового"
rules_have nat MEX_PREROUTING "203.0.113.30:443" "DNAT не перешёл на новый адрес"
rules_lack nat MEX_PREROUTING "203.0.113.10:443" "старый адрес остался в DNAT"

# Домен: липкий выбор A-записи и смена, когда старый адрес исчез.
getent="${MEX_TEST_TMP}/getent"
hosts="${MEX_TEST_TMP}/hosts.map"
cat >"$getent" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "ahostsv4" && -n "${MEX_HOSTS_MAP:-}" && -f "$MEX_HOSTS_MAP" ]]; then
  awk -v h="$2" '$1 == h { for (i = 2; i <= NF; i++) print $i, "STREAM", h }' "$MEX_HOSTS_MAP"
  exit 0
fi
exit 2
EOF
chmod 755 "$getent"
export PATH="${MEX_TEST_TMP}:${PATH}"
export MEX_HOSTS_MAP="$hosts"
printf '%s\n' "exit.example.test 203.0.113.10 203.0.113.11" >"$hosts"
cat >"$MEX_CONFIG_FILE" <<'JSON'
{
  "version": 2,
  "exits": [
    {
      "id": "dns-1",
      "name": "DNS",
      "host": "exit.example.test",
      "forwards": [
        {"proto": "tcp", "listen": 25000, "target": 443},
        {"proto": "udp", "listen": 25000, "target": 443}
      ]
    }
  ]
}
JSON
assert_ok mex_apply_from_config
assert_eq "$(jq -r '.resolved["dns-1"].selected' "$MEX_STATE_FILE")" "203.0.113.10" "первый A"
rules_have nat MEX_PREROUTING "203.0.113.10:443" "DNAT не на первый A"
printf '%s\n' "exit.example.test 203.0.113.11 203.0.113.10" >"$hosts"
assert_ok mex_apply_from_config
assert_eq "$(jq -r '.resolved["dns-1"].selected' "$MEX_STATE_FILE")" "203.0.113.10" "липкий A"
printf '%s\n' "exit.example.test 203.0.113.12" >"$hosts"
assert_ok mex_apply_from_config
assert_eq "$(jq -r '.resolved["dns-1"].selected' "$MEX_STATE_FILE")" "203.0.113.12" "новый A после ухода старого"
rules_have nat MEX_PREROUTING "203.0.113.12:443" "DNAT не сменил адрес домена"

# Сбой DNS не снимает правила, если адрес уже известен.
printf '%s\n' "" >"$hosts"
assert_ok mex_apply_from_config
assert_eq "$(jq -r '.resolved["dns-1"].stale' "$MEX_STATE_FILE")" "true" "stale при сбое DNS"
rules_have nat MEX_PREROUTING "203.0.113.12:443" "при сбое DNS правила сняты"

run_relay() {
  env \
    MEX_CONFIG_DIR="$MEX_CONFIG_DIR" \
    MEX_CONFIG_FILE="$MEX_CONFIG_FILE" \
    MEX_STATE_FILE="$MEX_STATE_FILE" \
    MEX_BACKUP_DIR="$MEX_BACKUP_DIR" \
    MEX_LOG_FILE="$MEX_LOG_FILE" \
    MEX_LOCK_FILE="$MEX_LOCK_FILE" \
    MEX_SYSCTL_FILE="$MEX_SYSCTL_FILE" \
    MEX_SYSTEMD_UNIT="$MEX_SYSTEMD_UNIT" \
    MEX_INSTALL_DIR="$MEX_INSTALL_DIR" \
    MEX_BIN_DIR="$MEX_BIN_DIR" \
    MEX_DRY_RUN=1 \
    MEX_DRY_RUN_LOG="$MEX_DRY_RUN_LOG" \
    MEX_SIM_DIR="$MEX_SIM_DIR" \
    MEX_SKIP_DEPS=1 \
    MEX_SKIP_ROOT=1 \
    MEX_SKIP_SYSTEMD=1 \
    MEX_SKIP_CLI=1 \
    MEX_SKIP_HOST_INTEGRATION=1 \
    MEX_SKIP_NETFILTER_SAVE=1 \
    MEX_SKIP_OS_CHECK=1 \
    MEX_SKIP_LOCK=1 \
    MEX_ASSUME_ROUTE=1 \
    MEX_PUBLIC_IP="198.51.100.5" \
    MEX_EGRESS_IFACE="eth0" \
    MEX_SOURCE_DIR="$MEX_REPO_ROOT" \
    MEX_TCP_STUB_FILE="$MEX_TCP_STUB_FILE" \
    MEX_SS_BIN="$MEX_SS_BIN" \
    MEX_SS_DATA="$MEX_SS_DATA" \
    MEX_SS_UDP_DATA="$MEX_SS_UDP_DATA" \
    MEX_HOSTS_MAP="$MEX_HOSTS_MAP" \
    PATH="$PATH" \
    bash "$MEX_REPO_ROOT/relay" "$@"
}

out="$(run_relay version --json)"
printf '%s\n' "$out" | jq -e '.ok == true and .name == "multi-exit-relay" and .version == "2.0.0"' >/dev/null || fail "version --json: ${out}"
[[ "$out" == "{"* ]] || fail "version --json не начинается с JSON"

rc=0
out="$(run_relay check --json)" || rc=$?
assert_eq "$rc" "0" "check --json код"
printf '%s\n' "$out" | jq -e '
  .ok == true and .command == "check" and .config_version == 2
  and (.exits[0].id == "dns-1")
  and (.exits[0].forwards[] | select(.proto=="tcp") | .rule_present == true and .reachable == true and .reachability == "ok")
  and (.exits[0].forwards[] | select(.proto=="udp") | .rule_present == true and .reachable == null and .reachability == "not_checkable")
' >/dev/null || fail "check --json тело: ${out}"

# stdout чистый, даже если журнал не подавлен.
noisy="$(MEX_QUIET=0 run_relay status --json 2>"${MEX_TEST_TMP}/status.err")"
printf '%s\n' "$noisy" | jq -e '.command == "status" and .ok == true' >/dev/null || fail "status --json: ${noisy}"
[[ "$noisy" != *"Ошибка"* && "$noisy" == "{"* ]] || fail "status --json смешал журнал в stdout"

# Недоступный TCP — код 4, UDP сам по себе проверку не роняет.
printf '%s\n' "203.0.113.12:443 fail" "203.0.113.12:* fail" >"$MEX_TCP_STUB_FILE"
rc=0
bad="$(run_relay check --json)" || rc=$?
assert_eq "$rc" "4" "check недоступного TCP"
printf '%s\n' "$bad" | jq -e '.ok == false and any(.problems[]; .code=="tcp_unreachable")' >/dev/null || fail "нет tcp_unreachable: ${bad}"

rc=0
run_relay apply --config "${MEX_TEST_TMP}/no-such.json" >/dev/null 2>&1 || rc=$?
assert_eq "$rc" "2" "apply чужого пути"

v1="${MEX_TEST_TMP}/legacy.json"
cat >"$v1" <<'JSON'
{
  "version": 1,
  "public_ip": "198.51.100.5",
  "egress_interface": "eth0",
  "next_seq": 2,
  "exits": [
    {
      "id": "exit-1",
      "name": "Старый",
      "ip": "203.0.113.15",
      "relay_port_443": 15000,
      "relay_port_8443": 15001,
      "exit_port_443": 443,
      "exit_port_8443": 8443,
      "status": "active"
    }
  ]
}
JSON
# Вернуть успешный stub, иначе это не про apply.
for i in $(seq 1 30); do
  printf '%s\n' "203.0.113.${i}:* ok" >>"$MEX_TCP_STUB_FILE"
done
rc=0
apply_out="$(run_relay apply --config "$v1" --json)" || rc=$?
assert_eq "$rc" "0" "apply --config v1"
printf '%s\n' "$apply_out" | jq -e '.ok == true and .command == "apply" and .config_version == 2 and .rules_added >= 1' >/dev/null \
  || fail "apply --json: ${apply_out}"
assert_eq "$(jq -r '.version' "$MEX_CONFIG_FILE")" "2" "v1 записан как v2"
assert_eq "$(jq -r '.exits[0].host' "$MEX_CONFIG_FILE")" "203.0.113.15" "v1 host"
rules_have nat MEX_PREROUTING "203.0.113.15:443" "v1 не применился"

# Неинтерактивная установка идемпотентна.
inst="${MEX_TEST_TMP}/inst"
mkdir -p "$inst"
rc=0
install_env() {
  env \
    MEX_SKIP_ROOT=1 MEX_SKIP_DEPS=1 MEX_SKIP_OS_CHECK=1 MEX_DRY_RUN=1 MEX_SKIP_LOCK=1 \
    MEX_SKIP_CLI=0 MEX_SKIP_SYSTEMD=0 MEX_SKIP_HOST_INTEGRATION=0 \
    MEX_CONFIG_DIR="${inst}/cfg" \
    MEX_CONFIG_FILE="${inst}/cfg/config.json" \
    MEX_STATE_FILE="${inst}/cfg/state.json" \
    MEX_BACKUP_DIR="${inst}/cfg/backups" \
    MEX_LOG_FILE="${inst}/cfg/logs/relay.log" \
    MEX_LOCK_FILE="${inst}/lock" \
    MEX_SYSCTL_FILE="${inst}/sysctl.conf" \
    MEX_SYSTEMD_UNIT="${inst}/multi-exit-relay.service" \
    MEX_INSTALL_DIR="${inst}/opt" \
    MEX_BIN_DIR="${inst}/bin" \
    MEX_PUBLIC_IP="198.51.100.5" \
    MEX_EGRESS_IFACE="eth0" \
    bash "$MEX_REPO_ROOT/install.sh" --non-interactive
}
install_env >/dev/null
install_env >/dev/null
[[ -x "${inst}/opt/relay" ]] || fail "relay не скопирован"
[[ -L "${inst}/bin/relay" ]] || fail "ссылка relay не создана"
[[ -f "${inst}/multi-exit-relay.service" ]] || fail "нет unit"
[[ -f "${inst}/multi-exit-relay-resolve.timer" ]] || fail "нет timer"
grep -q 'OnUnitActiveSec=5min' "${inst}/multi-exit-relay-resolve.timer" || fail "таймер не 5 минут"
grep -q 'relay apply' "${inst}/multi-exit-relay-resolve.service" || fail "timer не вызывает apply"
assert_eq "$(jq -r '.version' "${inst}/cfg/config.json")" "2" "пустой config v2"
assert_eq "$(jq -r '.exits | length' "${inst}/cfg/config.json")" "0" "установка не выдумывает Exit"

printf '%s\n' "OK contract"
