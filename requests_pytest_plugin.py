# This is necessary because we pull in requests' test suite,
# which sometimes tests `session.mount()`. We disable that
# method, so we need to ignore tests that use it.

import pytest

from advocate.exceptions import MountDisabledException, ProxyDisabledException

SKIP_EXCEPTIONS = (MountDisabledException, ProxyDisabledException)


def pytest_runtest_makereport(item, call):
    from _pytest.runner import pytest_runtest_makereport as mr
    report = mr(item, call)

    if call.excinfo is not None:
        if call.excinfo.type in SKIP_EXCEPTIONS:
            report.outcome = 'skipped'
            report.wasxfail = "reason: Advocate is not meant to support this"

    return report
