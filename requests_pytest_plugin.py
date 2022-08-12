import doctest
import ipaddress
import os
import socket

import requests
import urllib3

import advocate
import advocate.api
from advocate.exceptions import MountDisabledException, ProxyDisabledException

from test.monkeypatching import CheckedSocket


SKIP_EXCEPTIONS = (MountDisabledException, ProxyDisabledException)
IGNORED_ASSERT_PREFIXES = (
    # We use a newer version of pytest-httpbin where this won't happen!
    "assert () == ('SubjectAltNameWarning',)",
    # This happens in utils tests due to an stdlib change. Not our fault!
    "assert 'http:////example.com/path' == 'http://example.com/path'",
)


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

    wanted_requests_version = os.environ.get("WANTED_REQUESTS_VERSION")
    if wanted_requests_version and wanted_requests_version != requests.__version__:
        raise RuntimeError("Expected requests " + wanted_requests_version +
                           ", got " + requests.__version__)

    wanted_urllib3_version = os.environ.get("WANTED_URLLIB3_VERSION")
    if wanted_urllib3_version and wanted_urllib3_version != urllib3.__version__:
        raise RuntimeError("Expected urllib3 " + wanted_urllib3_version +
                           ", got " + urllib3.__version__)

    try:
        requests.get("http://192.168.0.1")
    except advocate.UnacceptableAddressException:
        return
    raise RuntimeError("Requests patching failed, can't run patched requests test suite!")


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
        if isinstance(exc, AssertionError):
            if exc.args and any(exc.args[0].startswith(prefix) for prefix in IGNORED_ASSERT_PREFIXES):
                report.outcome = 'skipped'
                report.wasxfail = "reason: Outdated assertion: %s" % exc.args[0]

    return report
