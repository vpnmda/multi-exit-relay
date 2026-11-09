#!/usr/bin/env bash
set -Eeuo pipefail
# shellcheck source=helpers.sh
source "$(dirname "$0")/helpers.sh"
setup_dry_env
load_libs

assert_ok mex_valid_ipv4 1.2.3.4
assert_ok mex_valid_ipv4 10.0.0.1
assert_ok mex_valid_ipv4 192.168.1.1
assert_ok mex_valid_ipv4 172.16.5.5
assert_ok mex_valid_ipv4 203.0.113.10
assert_ok mex_valid_ipv4 8.8.8.8
assert_fail mex_valid_ipv4 256.1.1.1
assert_fail mex_valid_ipv4 1.2.3
assert_fail mex_valid_ipv4 1.2.3.4.5
assert_fail mex_valid_ipv4 01.2.3.4
assert_fail mex_valid_ipv4 1.02.3.4
assert_fail mex_valid_ipv4 ""
assert_fail mex_valid_ipv4 0.0.0.0
assert_fail mex_valid_ipv4 0.1.2.3
assert_fail mex_valid_ipv4 127.0.0.1
assert_fail mex_valid_ipv4 224.0.0.1
assert_fail mex_valid_ipv4 255.255.255.255
assert_fail mex_valid_ipv4 "1.2.3.4 "
assert_fail mex_valid_ipv4 abc

assert_ok mex_valid_port 1
assert_ok mex_valid_port 22
assert_ok mex_valid_port 443
assert_ok mex_valid_port 65535
assert_fail mex_valid_port 0
assert_fail mex_valid_port 65536
assert_fail mex_valid_port 01
assert_fail mex_valid_port -1
assert_fail mex_valid_port abc
assert_fail mex_valid_port ""

assert_ok mex_valid_name "Германия"
assert_ok mex_valid_name "DE-1"
assert_fail mex_valid_name ""
assert_fail mex_valid_name $'Германия\n'
assert_fail mex_valid_name 'bad"name'
assert_fail mex_valid_name 'bad|name'
assert_fail mex_valid_name 'bad\name'
long="$(printf 'a%.0s' {1..65})"
assert_fail mex_valid_name "$long"
ok64="$(printf 'a%.0s' {1..64})"
assert_ok mex_valid_name "$ok64"

assert_ok mex_valid_exit_id exit-1
assert_ok mex_valid_exit_id exit-12
assert_fail mex_valid_exit_id exit-0
assert_fail mex_valid_exit_id exit-01
assert_fail mex_valid_exit_id "exit-1;rm"
assert_fail mex_valid_exit_id mex

assert_ok mex_valid_iface_name eth0
assert_ok mex_valid_iface_name ens3
assert_fail mex_valid_iface_name ""
assert_fail mex_valid_iface_name "bad iface"
assert_fail mex_valid_iface_name "this-name-is-too-long"

printf '%s\n' '{"version":1,"exits":[{"id":"exit-1","name":"A","ip":"203.0.113.10","relay_port_443":443,"relay_port_8443":8443,"exit_port_443":443,"exit_port_8443":8443,"status":"active"}]}' \
  | mex_atomic_write "$MEX_CONFIG_FILE"
assert_ok mex_config_validate_file "$MEX_CONFIG_FILE"
assert_ok mex_config_has_ip 203.0.113.10
assert_fail mex_config_has_ip 203.0.113.11

printf '%s\n' '{"version":2,"exits":[]}' | mex_atomic_write "${MEX_TEST_TMP}/bad.json"
assert_fail mex_config_validate_file "${MEX_TEST_TMP}/bad.json"

assert_ok mex_config_validate_file "${MEX_REPO_ROOT}/config/example.json"

printf '%s\n' "OK validation"
