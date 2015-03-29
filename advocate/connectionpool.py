from requests.packages.urllib3 import HTTPConnectionPool, HTTPSConnectionPool

from .connection import (
    BlacklistingHTTPConnection,
    BlacklistingHTTPSConnection,
)


class BlacklistingHTTPConnectionPool(HTTPConnectionPool):
    scheme = 'http'
    ConnectionCls = BlacklistingHTTPConnection


class BlacklistingHTTPSConnectionPool(HTTPSConnectionPool):
    scheme = 'https'
    ConnectionCls = BlacklistingHTTPSConnection
