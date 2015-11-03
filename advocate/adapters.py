from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK

from .addrvalidator import AddrValidator
from .poolmanager import ValidatingPoolManager


class ValidatingHTTPAdapter(HTTPAdapter):
    __attrs__ = HTTPAdapter.__attrs__ + ['_validator']

    def __init__(self, *args, **kwargs):
        self._validator = kwargs.pop('validator', None)
        if not self._validator:
            self._validator = AddrValidator()
        super(ValidatingHTTPAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK,
                         **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        # XXX: This would be unnecessary if the parent used a class-level
        # `PoolManagerCls` attr here. Possible patch for urllib3?
        self.poolmanager = ValidatingPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            validator=self._validator,
            **pool_kwargs
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """Return urllib3 ProxyManager for the given proxy.

        This method should not be called from user code, and is only
        exposed for use when subclassing the
        :class:`HTTPAdapter <requests.adapters.HTTPAdapter>`.

        :param proxy: The proxy to return a urllib3 ProxyManager for.
        :param proxy_kwargs: Extra keyword arguments used to configure the Proxy Manager.
        :returns: ProxyManager
        """
        raise NotImplementedError("Proxy support not ready")
        # TODO: Look into urllib3 internals to see what _proper_ proxy support
        # would entail
        # if proxy not in self.proxy_manager:
        #     proxy_headers = self.proxy_headers(proxy)
        #     # proxy itself if it's internal, but we want to use the validator
        #     # if we bypassed the proxy for a request.
        #     self.proxy_manager[proxy] = proxy_from_url(
        #         proxy,
        #         proxy_headers=proxy_headers,
        #         num_pools=self._pool_connections,
        #         maxsize=self._pool_maxsize,
        #         block=self._pool_block,
        #         validator=self._validator,
        #         **proxy_kwargs)
        #
        # return self.proxy_manager[proxy]
