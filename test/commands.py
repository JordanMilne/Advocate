import contextlib
import os
import sys

from setuptools.command.test import test as TestCommand


@contextlib.contextmanager
def pushd(path):
    old_cwd = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(old_cwd)


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


class PyTestRequestsCompliance(TestCommand):
    user_options = [
        ('requests-location=', 'l', 'Location of requests tests'),
        ('pytest-args=', 'a', "Arguments to pass to py.test"),
    ]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []
        self.requests_location = ""

    def finalize_options(self):
        if not self.requests_location:
            raise Exception("requests-location parameter is required!")
        self.requests_location = os.path.abspath(self.requests_location)
        if not self.requests_location.endswith(".py"):
            self.requests_location += "/"
        if self.pytest_args:
            self.pytest_args = [self.pytest_args]
        self.pytest_args.extend(("-x", self.requests_location))
        return TestCommand.finalize_options(self)

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest

        import advocate
        import advocate.packages.ipaddress as ipaddress
        from test.monkeypatching import AdvocateEnforcer

        # We need to change to the checkout dir, requests' test suite expects certain files
        # to be in the CWD.
        with pushd(self.requests_location):
            validator = advocate.AddrValidator(
                ip_whitelist={
                    # requests needs to be able to hit these for its tests!
                    ipaddress.ip_network("127.0.0.1"),
                    ipaddress.ip_network("127.0.1.1"),
                    ipaddress.ip_network("10.255.255.1"),
                },
                # the `httpbin` fixture uses a random fixture, we need to allow all ports
                port_whitelist=set(range(0, 65535)),
            )
            enforcer = AdvocateEnforcer(validator)
            with enforcer.monkeypatch_requests_module():
                errno = pytest.main(self.pytest_args, plugins=["requests_pytest_plugin"])
                sys.exit(errno)
