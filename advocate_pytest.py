# This is necessary because we pull in requests' test suite,
# which sometimes tests `session.mount()`. We disable that
# method, so we need to ignore tests that use it.

import pytest
from _pytest.runner import TestReport
from py._code.code import ExceptionInfo

from advocate.exceptions import MountDisabledException


def pytest_runtest_makereport(item, call):
    when = call.when
    duration = call.stop-call.start
    keywords = dict([(x,1) for x in item.keywords])
    excinfo = call.excinfo
    sections = []
    if not call.excinfo:
        outcome = "passed"
        longrepr = None
    else:
        if not isinstance(excinfo, ExceptionInfo):
            outcome = "failed"
            longrepr = excinfo
        elif excinfo.errisinstance((pytest.skip.Exception, MountDisabledException)):
            outcome = "skipped"
            r = excinfo._getreprcrash()
            longrepr = (str(r.path), r.lineno, r.message)
        else:
            outcome = "failed"
            if call.when == "call":
                longrepr = item.repr_failure(excinfo)
            else: # exception in setup or teardown
                longrepr = item._repr_failure_py(excinfo,
                                            style=item.config.option.tbstyle)
    for rwhen, key, content in item._report_sections:
        sections.append(("Captured %s %s" %(key, rwhen), content))
    return TestReport(item.nodeid, item.location,
                      keywords, outcome, longrepr, when,
                      sections, duration)
