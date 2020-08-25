#!/bin/sh

iface=$1
vendor=`lshw -short | grep $iface | awk '{print $4 " " $5 " " $6 " " $7}'`
echo $vendor > $2
