#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.chitacore/chitad.pid file instead
chita_pid=$(<~/.chitacore/testnet3/chitad.pid)
sudo gdb -batch -ex "source debug.gdb" chitad ${chita_pid}
