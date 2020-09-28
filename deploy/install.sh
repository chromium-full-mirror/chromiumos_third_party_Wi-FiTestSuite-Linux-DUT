#!/bin/bash
#
# Installs Wi-Fi Test Suite Linux Control Agent to the specified DUT.

if [[ $# -eq 0 || $1 == "--help" || $1 == "-h" ]]; then
  echo "Install wfa_ca and wfa_dut to the DUT."
  echo "Usage: ./install.sh \$DUT_HOST"
  exit 0
fi

WFA_DIR=/usr/local/bin/wfa
DUT_HOST=$1

# Load run_dut and deploy_dut functions.
MY_DIR=$( dirname "${BASH_SOURCE[0]}" )
source $MY_DIR/dut.sh

# Change working directory to the base dir of the package.
cd $MY_DIR/..

echo "Stopping existing wfa_ca and wfa_dut on $DUT_HOST"
run_dut mkdir -p $WFA_DIR
deploy_dut scripts/stop_wfa_ca_dut
run_dut $WFA_DIR/stop_wfa_ca_dut

echo "Deploying wfa_ca, wfa_dut and scripts to $DUT_HOST:$WFA_DIR"
deploy_dut ca/wfa_ca dut/wfa_dut
deploy_dut scripts/*
