#!/bin/bash

PKGNAME=wfa_ca
PKGFILE=$PKGNAME.zip

if [ $# -ne 1 ]; then
  echo "Usage: ./package.sh <path to identity file (testing_rsa)>"
  exit 1
fi
IDENTITY_SRC=$1
if [ ! -f $IDENTITY_SRC ]; then
  echo "File not found: $IDENTITY_SRC"
  exit 1
fi

MYDIR=$( dirname "${BASH_SOURCE[0]}" )
cd $MYDIR/..
BASE=$( pwd )

TMPD=$( mktemp -d )
PKGDIR=$TMPD/$PKGNAME
echo "Copying files to $PKGDIR"
mkdir -p $PKGDIR/ca
cp ca/wfa_ca $PKGDIR/ca

mkdir -p $PKGDIR/dut
cp dut/wfa_dut $PKGDIR/dut

cp -a deploy $PKGDIR
cp -a scripts $PKGDIR

IDENTITY_DEST=$PKGDIR/deploy/testing_rsa
cp $IDENTITY_SRC $IDENTITY_DEST
chmod 600 $IDENTITY_DEST

cd $TMPD
echo "Zipping $PKGNAME to $PKGFILE"
zip -q -r $PKGFILE $PKGNAME
mv $PKGFILE $BASE
rm -rf $TMPD

echo "Done. Package: $BASE/$PKGFILE"
