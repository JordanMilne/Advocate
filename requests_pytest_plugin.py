import socket

import doctest
import pytest
import requests

import advocate
import advocate.api

from advocate.exceptions import MountDisabledException, ProxyDisabledException
from advocate.packages import ipaddress
from test.monkeypatching import CheckedSocket


SKIP_EXCEPTIONS = (MountDisabledException, ProxyDisabledException)


def pytest_runtestloop():
    validator = advocate.AddrValidator(
        ip_whitelist={
            # requests needs to be able to hit these for its tests!
            ipaddress.ip_network("127.0.0.1"),
            ipaddress.ip_network("127.0.1.1"),
            ipaddress.ip_network("10.255.255.1"),
        },
        # the `httpbin` fixture uses a random port, we need to allow all ports
        port_whitelist=set(range(0, 65535)),
    )

    # this will yell at us if we failed to patch something
    socket.socket = CheckedSocket

    # requests' tests rely on being able to pickle a `Session`
    advocate.api.RequestsAPIWrapper.SUPPORT_WRAPPER_PICKLING = True
    wrapper = advocate.api.RequestsAPIWrapper(validator)

    for attr in advocate.api.__all__:
        setattr(requests, attr, getattr(wrapper, attr))


def pytest_runtest_makereport(item, call):
    # This is necessary because we pull in requests' test suite,
    # which sometimes tests `session.mount()`. We disable that
    # method, so we need to ignore tests that use it.

    from _pytest.runner import pytest_runtest_makereport as mr
    report = mr(item, call)

    if call.excinfo is not None:
        exc = call.excinfo.value
        if isinstance(exc, doctest.UnexpectedException):
            exc = call.excinfo.value.exc_info[1]

        if isinstance(exc, SKIP_EXCEPTIONS):
            report.outcome = 'skipped'
            report.wasxfail = "reason: Advocate is not meant to support this"

    return report
