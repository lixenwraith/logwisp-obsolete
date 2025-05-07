#!/bin/bash
pwd
source ./script/make.sh -c linux.make
bin/logwisp_linux -config config/logwisp.toml