#!/bin/bash

# The version of netifaces on PyPi is jacked up on Python 3, but
# HG tip works fine :(
if [[ ${TRAVIS_PYTHON_VERSION%%.*} == '3' || $TRAVIS_PYTHON_VERSION == 'pypy3' ]]; then
    pushd /tmp
    hg clone https://bitbucket.org/al45tair/netifaces netifaces
    pushd netifaces
    python setup.py install
    popd
    popd
fi
