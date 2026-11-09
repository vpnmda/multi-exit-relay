#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=helpers.sh
source "$(dirname "$0")/helpers.sh"
setup_dry_env
load_libs

read -r p1 p2 < <(mex_ports_default_pair 1)
assert_eq "$p1" 443 "слот 1 порт 1"
assert_eq "$p2" 8443 "слот 1 порт 2"
read -r p1 p2 < <(mex_ports_default_pair 2)
assert_eq "$p1" 10443 "слот 2 порт 1"
assert_eq "$p2" 18443 "слот 2 порт 2"
read -r p1 p2 < <(mex_ports_default_pair 3)
assert_eq "$p1" 20443 "слот 3 порт 1"
assert_eq "$p2" 28443 "слот 3 порт 2"
read -r p1 p2 < <(mex_ports_default_pair 4)
assert_eq "$p1" 30443 "слот 4 порт 1"
assert_eq "$p2" 38443 "слот 4 порт 2"
read -r p1 p2 < <(mex_ports_default_pair 5)
assert_eq "$p1" 40443 "слот 5 порт 1"
assert_eq "$p2" 48443 "слот 5 порт 2"
read -r p1 p2 < <(mex_ports_default_pair 6)
assert_eq "$p1" 50443 "слот 6 порт 1"
assert_eq "$p2" 58443 "слот 6 порт 2"
assert_fail mex_ports_default_pair 7
assert_fail mex_ports_default_pair 0

mex_ports_reset
read -r p1 p2 < <(mex_ports_find_free_pair)
assert_eq "$p1 $p2" "443 8443" "пустой набор занимает первый слот"

mex_ports_reset
mex_ports_mark 443
read -r p1 p2 < <(mex_ports_find_free_pair)
assert_eq "$p1 $p2" "10443 18443" "занятый 443 сдвигает пару целиком"

mex_ports_reset
mex_ports_mark 8443
read -r p1 p2 < <(mex_ports_find_free_pair)
assert_eq "$p1 $p2" "10443 18443" "занятый 8443 тоже сдвигает пару"

mex_ports_reset
for n in 1 2 3 4 5 6; do
  read -r a b < <(mex_ports_default_pair "$n")
  mex_ports_mark "$a" "$b"
done
read -r p1 p2 < <(mex_ports_find_free_pair)
assert_eq "$p1 $p2" "11443 19443" "после шести слотов берётся следующая пара"
assert_ok mex_valid_port "$p1"
assert_ok mex_valid_port "$p2"
(( p1 <= 65535 && p2 <= 65535 )) || fail "пара вне диапазона"

mex_ports_reset
mex_ports_mark 22
assert_fail mex_ports_pair_free 22 8443
assert_fail mex_ports_pair_free 443 443
assert_fail mex_ports_pair_free 0 8443
assert_fail mex_ports_pair_free 70000 8443
assert_ok mex_ports_pair_free 25000 26000

printf '%s\n' "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*" >"$MEX_SS_DATA"
mex_ports_collect_all
assert_ok mex_ports_is_occupied 443
assert_ok mex_ports_is_occupied 22
read -r p1 p2 < <(mex_ports_find_free_pair)
assert_eq "$p1 $p2" "10443 18443" "слушатель ss занимает 443"

: >"$MEX_SS_DATA"
mex_ports_reset
mex_iptables -t nat -N FOREIGN_NAT >/dev/null
mex_iptables -t nat -A PREROUTING -p tcp --dport 10443 -m comment --comment foreign-dnat -j DNAT --to-destination 198.51.100.9:443
mex_ports_collect_all
assert_ok mex_ports_is_occupied 10443
read -r p1 p2 < <(mex_ports_find_free_pair)
assert_eq "$p1 $p2" "443 8443" "чужой DNAT на 10443 не занимает первый слот"

printf '%s\n' "OK ports"
