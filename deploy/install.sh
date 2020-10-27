#!/bin/bash
#
# Installs Wi-Fi Test Suite Linux Control Agent to the specified DUT.

if [[ $# -eq 0 || $1 == "--help" || $1 == "-h" ]]; then
  echo "Install wfa_ca and wfa_dut to the DUT."
  echo "Usage: ./install.sh \$DUT_HOST"
  exit 0
fi

DUT_HOST=$1
WFA_BIN=/usr/local/bin
WFA_LIBEXE=/usr/local/libexe/wfa

# Load run_dut and deploy_dut functions.
MY_DIR=$( dirname "${BASH_SOURCE[0]}" )
source $MY_DIR/dut.sh

# Change working directory to the base dir of the package.
cd $MY_DIR/..

echo "Stopping existing wfa_ca and wfa_dut on $DUT_HOST"
deploy bin/stop_wfa_ca_dut $WFA_BIN
run_dut stop_wfa_ca_dut

echo "Deploying wfa_ca, wfa_dut and start/stop scripts to $DUT_HOST:$WFA_BIN"
deploy bin/* $WFA_BIN

echo "Deploying helper scripts to $DUT_HOST:$WFA_LIBEXE"
run_dut mkdir -p $WFA_LIBEXE
deploy scripts/* $WFA_LIBEXE
