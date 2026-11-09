#!/usr/bin/env bash
# Сквозной тест в сетевых пространствах имён: клиент -> relay -> два Exit.
# Нужны root, iptables-nft и возможность создавать netns.
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -n bash "$0" "$@"
  fi
  printf '%s\n' "SKIP netns: нет root" >&2
  exit 0
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "${1:-}" == "--inside" ]]; then
  BASE="${MEX_E2E_BASE:?}"
else
  BASE="/tmp/mex-e2e-$$"
fi
CFG="${BASE}/cfg"
PY="${BASE}/listener.py"
PIDS="${BASE}/pids"

if [[ "${1:-}" == "--inside" ]]; then
  shift
  export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
  export MEX_CONFIG_DIR="$CFG"
  export MEX_CONFIG_FILE="${CFG}/config.json"
  export MEX_STATE_FILE="${CFG}/state.json"
  export MEX_BACKUP_DIR="${CFG}/backups"
  export MEX_LOG_FILE="${CFG}/logs/relay.log"
  export MEX_LOCK_FILE="${BASE}/lock"
  export MEX_SYSCTL_FILE="${BASE}/sysctl.conf"
  export MEX_SYSTEMD_UNIT="${BASE}/unit.service"
  export MEX_INSTALL_DIR="${BASE}/opt"
  export MEX_BIN_DIR="${BASE}/bin"
  export MEX_SOURCE_DIR="$REPO"
  export MEX_SKIP_DEPS=1
  export MEX_SKIP_SYSTEMD=1
  export MEX_SKIP_CLI=1
  export MEX_SKIP_HOST_INTEGRATION=1
  export MEX_SKIP_OS_CHECK=1
  export MEX_PUBLIC_IP="10.1.0.1"
  export MEX_EGRESS_IFACE="vr-c"
  export MEX_NETFILTER_SAVE_CMD="iptables-save > ${BASE}/rules.v4"
  export MEX_DRY_RUN=0
  export MEX_QUIET=1
  # shellcheck source=../lib/common.sh
  source "${REPO}/lib/common.sh"
  # shellcheck source=../lib/validation.sh
  source "${REPO}/lib/validation.sh"
  # shellcheck source=../lib/ports.sh
  source "${REPO}/lib/ports.sh"
  # shellcheck source=../lib/iptables.sh
  source "${REPO}/lib/iptables.sh"
  # shellcheck source=../lib/backup.sh
  source "${REPO}/lib/backup.sh"
  # shellcheck source=../lib/exits.sh
  source "${REPO}/lib/exits.sh"
  # shellcheck source=../lib/diagnostics.sh
  source "${REPO}/lib/diagnostics.sh"
  mex_init
  phase="$1"
  shift
  case "$phase" in
    foreign)
      iptables -P FORWARD DROP
      iptables -A INPUT -p tcp --dport 22 -m comment --comment foreign-ssh -j ACCEPT
      iptables -t nat -A PREROUTING -p tcp --dport 9 -m comment --comment foreign-dnat -j DNAT --to-destination 198.51.100.9:9
      iptables -t nat -A POSTROUTING -s 10.9.9.0/24 -m comment --comment foreign-masq -j MASQUERADE
      ;;
    add-conflict)
      mex_exit_add "Германия" "10.2.0.2"
      jq -r '.exits[0] | "\(.relay_port_443) \(.relay_port_8443)"' "$MEX_CONFIG_FILE"
      ;;
    remove-conflict)
      id="$(jq -r '.exits[0].id' "$MEX_CONFIG_FILE")"
      mex_exit_remove "$id"
      ;;
    add-two)
      mex_exit_add "Германия" "10.2.0.2"
      mex_exit_add "Нидерланды" "10.3.0.2"
      jq -r '.exits[] | [.id, .ip, .relay_port_443, .relay_port_8443] | @tsv' "$MEX_CONFIG_FILE"
      ;;
    add-four-more)
      MEX_ASSUME_ROUTE=1 mex_exit_add "Финляндия" "203.0.113.11" "" "" 1
      MEX_ASSUME_ROUTE=1 mex_exit_add "Швеция" "203.0.113.12" "" "" 1
      MEX_ASSUME_ROUTE=1 mex_exit_add "Польша" "203.0.113.13" "" "" 1
      MEX_ASSUME_ROUTE=1 mex_exit_add "Франция" "203.0.113.14" "" "" 1
      jq -r '.exits | length' "$MEX_CONFIG_FILE"
      ;;
    counts)
      printf 'dnat %s\n' "$(iptables -t nat -S MEX_PREROUTING | awk '/^-A /{c++} END{print c+0}')"
      printf 'masq %s\n' "$(iptables -t nat -S MEX_POSTROUTING | awk '/^-A /{c++} END{print c+0}')"
      printf 'fwd %s\n' "$(iptables -S MEX_FORWARD | awk '/^-A /{c++} END{print c+0}')"
      printf 'policy %s\n' "$(iptables -S FORWARD | awk 'NR==1 && $1=="-P" {print $3}')"
      if iptables -t mangle -S FORWARD | grep -q 'mex:tcpmss'; then
        printf '%s\n' "tcpmss yes"
      else
        printf '%s\n' "tcpmss no"
      fi
      ;;
    apply-again)
      mex_apply_from_config
      ;;
    remove-id)
      mex_exit_remove "$1"
      ;;
    wipe-own)
      iptables -D FORWARD -j MEX_FORWARD || true
      iptables -t nat -D PREROUTING -j MEX_PREROUTING || true
      iptables -t nat -D POSTROUTING -j MEX_POSTROUTING || true
      if iptables -S MEX_FORWARD >/dev/null 2>&1; then
        iptables -t filter -F MEX_FORWARD
        iptables -t filter -X MEX_FORWARD
      fi
      if iptables -t nat -S MEX_PREROUTING >/dev/null 2>&1; then
        iptables -t nat -F MEX_PREROUTING
        iptables -t nat -X MEX_PREROUTING
      fi
      if iptables -t nat -S MEX_POSTROUTING >/dev/null 2>&1; then
        iptables -t nat -F MEX_POSTROUTING
        iptables -t nat -X MEX_POSTROUTING
      fi
      iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment mex:tcpmss -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
      ;;
    uninstall)
      MEX_ASSUME_YES=1 mex_uninstall_system
      ;;
    assert-foreign)
      iptables -S INPUT | grep -q foreign-ssh
      iptables -t nat -S PREROUTING | grep -q foreign-dnat
      iptables -t nat -S POSTROUTING | grep -q foreign-masq
      policy="$(iptables -S FORWARD | awk 'NR==1 && $1=="-P" {print $3}')"
      [[ "$policy" == "DROP" ]]
      if iptables -S | grep -q 'MEX_'; then
        printf '%s\n' "наши цепочки ещё есть" >&2
        exit 1
      fi
      if iptables-save | grep -q 'mex:'; then
        printf '%s\n' "наши комментарии ещё есть" >&2
        exit 1
      fi
      ;;
    *)
      printf 'неизвестная фаза %s\n' "$phase" >&2
      exit 1
      ;;
  esac
  exit 0
fi

mkdir -p "$CFG" "${CFG}/logs" "$BASE"
cat >"$PY" <<'PY'
import socket, sys
ident, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(32)
while True:
    c, _ = s.accept()
    try:
        c.sendall((ident + "\n").encode())
        c.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    finally:
        c.close()
PY

cleanup() {
  if [[ -f "$PIDS" ]]; then
    while read -r pid; do
      kill "$pid" 2>/dev/null || true
    done <"$PIDS"
  fi
  local ns
  for ns in mex-client mex-relay mex-exit1 mex-exit2; do
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$ns"; then
      ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
      ip netns del "$ns" 2>/dev/null || true
    fi
  done
  rm -rf "$BASE"
}
dump_debug() {
  printf '%s\n' "----- debug relay iptables -----" >&2
  ip netns exec mex-relay iptables-save >&2 2>/dev/null || true
  printf '%s\n' "----- debug routes -----" >&2
  ip netns exec mex-relay ip route >&2 2>/dev/null || true
  printf '%s\n' "----- debug listeners -----" >&2
  ip netns exec mex-exit1 ss -lnt >&2 2>/dev/null || true
  ip netns exec mex-exit2 ss -lnt >&2 2>/dev/null || true
  ip netns exec mex-relay ss -lnt >&2 2>/dev/null || true
}
trap cleanup EXIT
trap 'dump_debug' ERR

for ns in mex-client mex-relay mex-exit1 mex-exit2; do
  ip netns del "$ns" 2>/dev/null || true
  ip netns add "$ns"
done

ip link add vr-c type veth peer name vc-r
ip link add vr-e1 type veth peer name ve1-r
ip link add vr-e2 type veth peer name ve2-r
ip link set vr-c netns mex-relay
ip link set vc-r netns mex-client
ip link set vr-e1 netns mex-relay
ip link set ve1-r netns mex-exit1
ip link set vr-e2 netns mex-relay
ip link set ve2-r netns mex-exit2

setup_ns() {
  local ns="$1" dev="$2" addr="$3"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "$addr" dev "$dev"
  ip netns exec "$ns" ip link set "$dev" up
}
setup_ns mex-client vc-r 10.1.0.2/30
setup_ns mex-relay vr-c 10.1.0.1/30
ip netns exec mex-relay ip addr add 10.2.0.1/30 dev vr-e1
ip netns exec mex-relay ip link set vr-e1 up
ip netns exec mex-relay ip addr add 10.3.0.1/30 dev vr-e2
ip netns exec mex-relay ip link set vr-e2 up
setup_ns mex-exit1 ve1-r 10.2.0.2/30
setup_ns mex-exit2 ve2-r 10.3.0.2/30

ip netns exec mex-relay sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec mex-relay sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
ip netns exec mex-relay sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
for dev in all default vr-c vr-e1 vr-e2 lo; do
  ip netns exec mex-relay sysctl -w "net.ipv4.conf.${dev}.rp_filter=0" >/dev/null || true
done

start_listener() {
  local ns="$1" ident="$2" port="$3"
  ip netns exec "$ns" python3 "$PY" "$ident" "$port" >"${BASE}/${ns}-${port}.log" 2>&1 &
  echo $! >>"$PIDS"
}

start_listener mex-exit1 exit1-443 443
start_listener mex-exit1 exit1-8443 8443
start_listener mex-exit2 exit2-443 443
start_listener mex-exit2 exit2-8443 8443
start_listener mex-relay relay-hold 443
sleep 0.4

ip netns exec mex-relay timeout 3 bash -c 'echo >/dev/tcp/10.2.0.2/443' || {
  printf '%s\n' "FAIL: relay не достучался до exit1:443 до DNAT" >&2
  exit 1
}

inside() {
  ip netns exec mex-relay env \
    PATH="/usr/sbin:/usr/bin:/sbin:/bin" \
    MEX_E2E_BASE="$BASE" \
    bash "$0" --inside "$@"
}

inside foreign

conflict="$(inside add-conflict)"
[[ "$conflict" == "10443 18443" ]] || {
  printf 'FAIL: занятый 443 должен дать другую пару, получено %s\n' "$conflict" >&2
  exit 1
}
inside remove-conflict
# Слушатель на relay:443 больше не нужен: стандартная пара должна освободиться.
if [[ -f "$PIDS" ]]; then
  while read -r pid; do
    kill "$pid" 2>/dev/null || true
  done <"$PIDS"
  : >"$PIDS"
fi
ip netns pids mex-relay | xargs -r kill 2>/dev/null || true
sleep 0.2
start_listener mex-exit1 exit1-443 443
start_listener mex-exit1 exit1-8443 8443
start_listener mex-exit2 exit2-443 443
start_listener mex-exit2 exit2-8443 8443
sleep 0.3

mapfile -t rows < <(inside add-two)
IFS=$'\t' read -r id1 ip1 p1a p1b <<<"${rows[0]}"
IFS=$'\t' read -r id2 ip2 p2a p2b <<<"${rows[1]}"
[[ "$id1" == exit-* && "$ip1" == "10.2.0.2" && "$p1a" == "443" && "$p1b" == "8443" ]] || {
  printf 'FAIL: неожиданные порты первого Exit: %s\n' "${rows[0]}" >&2
  exit 1
}
[[ "$id2" == exit-* && "$ip2" == "10.3.0.2" && "$p2a" == "10443" && "$p2b" == "18443" ]] || {
  printf 'FAIL: неожиданные порты второго Exit: %s\n' "${rows[1]}" >&2
  exit 1
}

client_fetch() {
  local port="$1"
  # shellcheck disable=SC2016
  ip netns exec mex-client timeout 3 bash -c '
    exec 3<>/dev/tcp/"$1"/"$2" || exit 2
    IFS= read -r -t 2 line <&3 || exit 3
    [[ -n "$line" ]] || exit 4
    printf "%s\n" "$line"
  ' bash 10.1.0.1 "$port"
}

flush_conntrack() {
  ip netns exec mex-relay conntrack -F >/dev/null 2>&1 || true
}

got="$(client_fetch 443)"
[[ "$got" == "exit1-443" ]] || { printf 'FAIL: порт 443 вернул [%s]\n' "$got" >&2; exit 1; }
got="$(client_fetch 8443)"
[[ "$got" == "exit1-8443" ]] || { printf 'FAIL: порт 8443 вернул [%s]\n' "$got" >&2; exit 1; }
got="$(client_fetch 10443)"
[[ "$got" == "exit2-443" ]] || { printf 'FAIL: порт 10443 вернул [%s]\n' "$got" >&2; exit 1; }
got="$(client_fetch 18443)"
[[ "$got" == "exit2-8443" ]] || { printf 'FAIL: порт 18443 вернул [%s]\n' "$got" >&2; exit 1; }

count1="$(inside counts)"
inside apply-again
count2="$(inside counts)"
[[ "$count1" == "$count2" ]] || {
  printf 'FAIL: повторное применение изменило набор правил\n%s\n%s\n' "$count1" "$count2" >&2
  exit 1
}
got="$(client_fetch 443)"
[[ "$got" == "exit1-443" ]] || { printf 'FAIL: после повторного apply порт 443 сломался\n' >&2; exit 1; }

extra="$(inside add-four-more)"
[[ "$extra" == "6" ]] || { printf 'FAIL: ожидалось 6 Exit, получено %s\n' "$extra" >&2; exit 1; }
got="$(client_fetch 10443)"
[[ "$got" == "exit2-443" ]] || { printf 'FAIL: шестой Exit сдвинул чужие порты\n' >&2; exit 1; }

inside remove-id "$id2"
flush_conntrack
if client_fetch 10443 >/dev/null 2>&1; then
  printf '%s\n' "FAIL: после удаления ${id2} порт 10443 всё ещё отвечает" >&2
  ip netns exec mex-relay iptables-save >&2 || true
  jq . "${CFG}/config.json" >&2 || true
  exit 1
fi
got="$(client_fetch 443)"
[[ "$got" == "exit1-443" ]] || { printf 'FAIL: exit-1 сломался после удаления exit-2\n' >&2; exit 1; }
ip netns exec mex-relay iptables -S INPUT | grep -q foreign-ssh
ip netns exec mex-relay iptables -t nat -S PREROUTING | grep -q foreign-dnat
ip netns exec mex-relay iptables -t nat -S POSTROUTING | grep -q foreign-masq
policy="$(ip netns exec mex-relay iptables -S FORWARD | awk 'NR==1 && $1=="-P" {print $3}')"
[[ "$policy" == "DROP" ]]

grep -q 'MEX_PREROUTING' "${BASE}/rules.v4"
grep -q 'foreign-ssh' "${BASE}/rules.v4"
cp -a "${BASE}/rules.v4" "${BASE}/rules-before-wipe.v4"

inside wipe-own
flush_conntrack
if client_fetch 443 >/dev/null 2>&1; then
  printf '%s\n' "FAIL: после снятия своих правил трафик всё ещё проходит" >&2
  exit 1
fi
inside apply-again
got="$(client_fetch 443)"
[[ "$got" == "exit1-443" ]] || { printf 'FAIL: apply не восстановил проброс из config.json\n' >&2; exit 1; }
ip netns exec mex-relay iptables -S INPUT | grep -q foreign-ssh
ip netns exec mex-relay iptables -t nat -S PREROUTING | grep -q foreign-dnat

inside uninstall
ip netns exec mex-relay bash -c 'iptables -S INPUT | grep -q foreign-ssh'
ip netns exec mex-relay bash -c 'iptables -t nat -S PREROUTING | grep -q foreign-dnat'
ip netns exec mex-relay bash -c 'iptables -t nat -S POSTROUTING | grep -q foreign-masq'
policy="$(ip netns exec mex-relay iptables -S FORWARD | awk 'NR==1 && $1=="-P" {print $3}')"
[[ "$policy" == "DROP" ]]
if ip netns exec mex-relay iptables-save | grep -q 'MEX_\|mex:'; then
  printf '%s\n' "FAIL: после uninstall остались наши правила" >&2
  exit 1
fi
flush_conntrack
if client_fetch 443 >/dev/null 2>&1; then
  printf '%s\n' "FAIL: после uninstall проброс ещё работает" >&2
  exit 1
fi
grep -q 'foreign-ssh' "${BASE}/rules.v4"
if grep -q 'MEX_' "${BASE}/rules.v4"; then
  printf '%s\n' "FAIL: снимок после uninstall всё ещё содержит наши цепочки" >&2
  exit 1
fi

# Снимок до очистки — полный дамп, которым пользуется netfilter-persistent.
# Продукт сам такой дамп в ядро не заливает. Здесь проверяется только,
# что сохранённый файл содержит и чужие, и наши правила.
grep -q 'foreign-ssh' "${BASE}/rules-before-wipe.v4"
grep -q 'MEX_PREROUTING' "${BASE}/rules-before-wipe.v4"
ip netns exec mex-relay iptables-restore <"${BASE}/rules-before-wipe.v4"
ip netns exec mex-relay iptables -S INPUT | grep -q foreign-ssh
ip netns exec mex-relay iptables -t nat -S MEX_PREROUTING >/dev/null
inside uninstall

printf '%s\n' "OK netns"
if ip netns exec mex-relay iptables -t mangle -S FORWARD | grep -q 'mex:tcpmss'; then
  printf '%s\n' "TCPMSS: правило есть в ядре"
else
  printf '%s\n' "TCPMSS: в этом ядре цель недоступна, правило не установилось (это зафиксировано, не скрыто)"
fi
