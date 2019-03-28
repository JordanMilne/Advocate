import contextlib
import os.path
import socket
import re
import sys
import traceback

from advocate import RequestsAPIWrapper


class DisallowedConnectException(Exception):
    pass


class CheckedSocket(socket.socket):
    CONNECT_ALLOWED_FUNCS = {"validating_create_connection"}
    # `test_testserver.py` makes raw connections to the test server to ensure it works
    CONNECT_ALLOWED_FILES = {"test_testserver.py"}
    _checks_enabled = True

    @classmethod
    @contextlib.contextmanager
    def bypass_checks(cls):
        try:
            cls._checks_enabled = False
            yield
        finally:
            cls._checks_enabled = True

    @classmethod
    def _check_frame_allowed(cls, frame):
        if os.path.basename(frame[0]) in cls.CONNECT_ALLOWED_FILES:
            return True
        if frame[2] in cls.CONNECT_ALLOWED_FUNCS:
            return True
        return False

    def connect(self, *args, **kwargs):
        if self._checks_enabled:

            stack = traceback.extract_stack()
            if not any(self._check_frame_allowed(frame) for frame in stack):
                raise DisallowedConnectException("calling socket.connect() unsafely!")
        return super(CheckedSocket, self).connect(*args, **kwargs)


class AdvocateEnforcer(object):
    """
    Forces all calls to `requests.(get/post/head/etc.)` to go through Advocate.

    Used when running requests' test suite to verify that Advocate is API-compatible.
    This is *NOT* appropriate for use in production.
    """
    __name__ = "requests"

    HOOKED_ATTRS = {"get", "post", "delete", "patch", "options", "put", "head", "session",
                    "Session", "request"}
    ADVOCATE_RE = re.compile(r'\Aadvocate(\.|\Z)')

    def __init__(self, validator):
        self._orig_module = None
        self._advocate_wrapper = RequestsAPIWrapper(validator)

    @classmethod
    def _inside_advocate_call(cls):
        """Check if we are already inside a function that's a part of Advocate"""
        advocate_files = set()
        for name, mod in sys.modules.items():
            if not mod:
                continue
            if name and cls.ADVOCATE_RE.match(name):
                advocate_files.add(mod.__file__)
        stack_files = [x[0] for x in traceback.extract_stack()]
        return advocate_files.intersection(stack_files)

    @contextlib.contextmanager
    def monkeypatch_requests_module(self):
        """Temporarily replace explicit requests calls with calls to Advocate"""
        try:
            assert not self._orig_module
            self._orig_module = sys.modules['requests']
            sys.modules['requests'] = self
            yield
        finally:
            if self._orig_module:
                sys.modules['requests'] = self._orig_module
            self._orig_module = None

    def __getattr__(self, item):
        # We're already inside an advocate call? Pass through to the original val
        should_hook = item in self.HOOKED_ATTRS
        if not should_hook or not self._orig_module or self._inside_advocate_call():
            return getattr(self._orig_module, item)
        return getattr(self._advocate_wrapper, item)
