from __future__ import absolute_import

try:
    # Try to pull from the global `ipaddress` module
    from ipaddress import *

    # Check that this package has everything we need (might be an old version
    # of `py2-ipaddress`)
    IPv4Network.is_global
except ImportError:
    # If we don't have one, use our bundled Python 2 version
    # XXX: Python 3 before 3.3 doesn't have the `ipaddress` module and will
    # break on this import.
    from .ipaddress import *
