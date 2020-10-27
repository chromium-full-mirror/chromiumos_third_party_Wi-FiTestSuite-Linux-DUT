#!/bin/bash
#
# Provides run_dut and deploy_dut functions.

# The real path of the script resides.
DEPLOY_PATH=$( realpath $( dirname "${BASH_SOURCE[0]}" ) )

IDENTITY=$DEPLOY_PATH/testing_rsa
SSH_CONFIG=$DEPLOY_PATH/ssh_config

# Check that identity file exists.
if [ ! -f $IDENTITY ]; then
   echo "Please copy testing_rsa to $IDENTITY, which can be found in"
   echo "https://chromium.googlesource.com/chromiumos/chromite/+/master/ssh_keys#"
   echo "Remember to run 'chmod 600 $IDENTITY'."
   exit 1
fi

# Run command on DUT.
function run_dut {
  ssh -i $IDENTITY -F $SSH_CONFIG $DUT_HOST $@
}

# Copy source file(s) to $DUT_HOST:${last_param}
function deploy {
  scp -i $IDENTITY -F $SSH_CONFIG ${@:1:$#-1} $DUT_HOST:${!#}
}
