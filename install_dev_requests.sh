#!/bin/bash
# installs requests in a way that lets us get at its
# test suite
mkdir -p ../dev_packages
pushd ../dev_packages
pip uninstall -y requests
git clone --branch "v${1}" --depth 1 "https://github.com/kennethreitz/requests.git" "requests-${1}"
set -e
pushd "requests-${1}"
pip install -e '.[security]'
popd
popd
