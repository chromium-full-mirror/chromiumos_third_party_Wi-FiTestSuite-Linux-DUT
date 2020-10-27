#!/bin/bash
#
# Starts / stops (wfa_ca, wfa_dut) pair remotely.
# Usage: ./wfa_ca_dut.sh (start|stop) $DUT_HOST

START_STOP=$1
DUT_HOST=$2

# Load run_dut and deploy_dut functions.
MY_DIR=$( dirname "${BASH_SOURCE[0]}" )
source $MY_DIR/dut.sh

case $START_STOP in
  start)
    run_dut start_wfa_ca_dut &
    echo "wfa_ca / wfa_dut started on $DUT_HOST"
    ;;
  stop)
    run_dut stop_wfa_ca_dut
    echo "wfa_ca / wfa_dut stopped on $DUT_HOST"
    ;;
  *)
    echo "Usage: ./wfa_ca_dut.sh (start|stop) \$DUT_HOST"
    ;;
esac
