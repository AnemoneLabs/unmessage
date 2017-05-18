#!/bin/bash
# script based on https://github.com/pyca/pynacl/blob/master/.travis/install.sh
set -ex
wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
tar zxvf LATEST.tar.gz
cd libsodium-*
./configure
make
make check
sudo make install
sudo ldconfig
