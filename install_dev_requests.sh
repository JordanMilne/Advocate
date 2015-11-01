#!/bin/bash
# installs requests in a way that lets us get at its
# test suite
mkdir -p dev_packages
pushd dev_packages
pip uninstall -y requests
easy_install -U --editable --build-directory . "${1}"
mv requests "${1}"
set -e
pushd "${1}"
python setup.py develop
popd
popd
