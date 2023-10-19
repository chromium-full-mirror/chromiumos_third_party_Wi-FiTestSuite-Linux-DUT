#!/bin/sh

# $1: function that evaluates a condition to check for.
wait_for_true_or_time_out() {
  local count
  for count in $(seq 0 1 20); do
    if "$@"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

supplicant_up() {
  local count
  count=$(wpa_cli.sh -i wlan0 quit 2>&1 | grep -c error)
  if [ "${count}" -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

modprobe -r iwlmvm iwlwifi
modprobe iwlwifi "$@"
restart wpasupplicant
restart shill
wait_for_true_or_time_out supplicant_up
exit $?
