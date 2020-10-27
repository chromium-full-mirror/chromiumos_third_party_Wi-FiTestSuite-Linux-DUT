#!/bin/bash

# Package WFA Test Suite's content to a zip file for deployment.
# It grabs the compiled binaries, helper scripts and DUT's SSH keys to
# pack in a zip file.
#
# Parameters: <testing_rsa_path> <board name to access /build/$board>
#
# Layout:
#   bin/: wfa_ca, wfa_dut and scripts in shbin/*
#   deploy/: deploy scripts in deploy/*
#   scripts: helper scripts in scripts/*



PKGNAME=wfa_ca
PKGFILE=$PKGNAME.zip

if [ $# -ne 2 ]; then
  echo "Usage: ./package.sh <path to identity file (testing_rsa)> <board name>"
  exit 1
fi
IDENTITY_SRC=$1
if [ ! -f $IDENTITY_SRC ]; then
  echo "File not found: $IDENTITY_SRC"
  exit 1
fi

BOARD=$2
BUILT_BIN=/build/$BOARD/usr/local/bin
if [ ! -f $BUILT_BIN/wfa_dut ]; then
  echo "File not found: $BUILT_BIN/wfa_dut. Are you in chroot? Please run emerge first"
  exit 1
fi

MYDIR=$( dirname "${BASH_SOURCE[0]}" )
cd $MYDIR/..
BASE=$( pwd )

TMPD=$( mktemp -d )
PKGDIR=$TMPD/$PKGNAME
echo "Copying files to $PKGDIR"
mkdir -p $PKGDIR/bin
cp $BUILT_BIN/wfa_ca $PKGDIR/bin
cp $BUILT_BIN/wfa_dut $PKGDIR/bin

cp -a deploy $PKGDIR
cp -a scripts $PKGDIR
cp -a shbin/* $PKGDIR/bin

IDENTITY_DEST=$PKGDIR/deploy/testing_rsa
cp $IDENTITY_SRC $IDENTITY_DEST
chmod 600 $IDENTITY_DEST

cd $TMPD
echo "Zipping $PKGNAME to $PKGFILE"
zip -q -r $PKGFILE $PKGNAME
mv $PKGFILE $BASE
rm -rf $TMPD

echo "Done. Package: $BASE/$PKGFILE"
