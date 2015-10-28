from __future__ import absolute_import

# XXX: Python 3 before 3.3 doesn't have the `ipaddress` module and will
# break on this import.
try:
    # First try to use our bundled ipaddress module
    from .ipaddress import *
except ImportError:
    # Try to pull from the global `ipaddress` module
    from ipaddress import *
