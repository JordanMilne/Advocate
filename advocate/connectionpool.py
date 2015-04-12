from requests.packages.urllib3 import HTTPConnectionPool, HTTPSConnectionPool

from .connection import (
    BlacklistingHTTPConnection,
    BlacklistingHTTPSConnection,
)

# Don't silently break if the private API changes across urllib3 versions
assert(hasattr(HTTPConnectionPool, 'ConnectionCls'))
assert(hasattr(HTTPSConnectionPool, 'ConnectionCls'))
assert(hasattr(HTTPConnectionPool, 'scheme'))
assert(hasattr(HTTPSConnectionPool, 'scheme'))


class BlacklistingHTTPConnectionPool(HTTPConnectionPool):
    scheme = 'http'
    ConnectionCls = BlacklistingHTTPConnection


class BlacklistingHTTPSConnectionPool(HTTPSConnectionPool):
    scheme = 'https'
    ConnectionCls = BlacklistingHTTPSConnection
