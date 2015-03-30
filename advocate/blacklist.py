# Try to use the "real" ipaddress before we try for the backported version.
try:
    import ipaddress
except ImportError:
    from .packages import ipaddress

from .exceptions import BlacklistException


class AdvocateBlacklist(object):
    _6TO4_RELAY_NET = ipaddress.ip_network("192.88.99.0/24")

    def __init__(
            self,
            ip_blacklist=None,
            port_whitelist=None,
            port_blacklist=None,
            allow_ipv6=False,
            allow_teredo=False,
            allow_6to4=False,
            allow_link_local=False,
            allow_loopback=False,
            allow_multicast=False,
            allow_private=False,
            allow_reserved=False,
            allow_site_local=False,
            allow_unspecified=False,
    ):
        self.ip_blacklist = ip_blacklist
        self.port_whitelist = port_whitelist
        self.port_blacklist = port_blacklist
        self.allow_ipv6 = allow_ipv6
        self.allow_teredo = allow_teredo
        self.allow_6to4 = allow_6to4
        self.allow_link_local = allow_link_local
        self.allow_loopback = allow_loopback
        self.allow_multicast = allow_multicast
        self.allow_private = allow_private
        self.allow_reserved = allow_reserved
        self.allow_site_local = allow_site_local
        self.allow_unspecified = allow_unspecified

    def is_ip_allowed(self, addr_ip):
        if not isinstance(addr_ip, ipaddress._BaseAddress):
            addr_ip = ipaddress.ip_address(addr_ip)

        if addr_ip.version == 4:
            if not self.allow_private and not addr_ip.is_private:
                # IPs for carrier-grade NAT. Seems weird that it doesn't set
                # `is_private`, but we need to check `not is_global`
                if not ipaddress.ip_network(addr_ip).is_global:
                    return False
        elif addr_ip.version == 6:
            # I'm erring towards disallowing IPv6 just because I don't have a
            # good grasp on it, but disabling it by default is
            # "bad for the internet" (tm)
            # allow by default once I've gained confidence in it.
            if not self.allow_ipv6:
                return False

            # v6 addresses can also map to IPv4 addresses! Tricky!
            v4_nested = []
            if addr_ip.ipv4_mapped:
                v4_nested.append(addr_ip.ipv4_mapped)
            # TODO: Doesn't look like `ipaddress` handles `64:ff9b::<ipv4>`?
            # Should still be handled if you don't `allow_reserved`

            # WTF IPv6? Why you gotta have a billion tunneling mechanisms?
            # XXX: Do we even really care about these? If we're tunneling
            # through public servers we shouldn't be able to access
            # addresses on our private network, right?
            if addr_ip.sixtofour:
                if not self.allow_6to4:
                    return False
                v4_nested.append(addr_ip.sixtofour)
            if addr_ip.teredo:
                if not self.allow_teredo:
                    return False
                # Check both the client *and* server IPs
                v4_nested.extend(addr_ip.teredo)

            if not all(self.is_ip_allowed(addr_v4) for addr_v4 in v4_nested):
                return False

            # fec0::*, apparently deprecated?
            if not self.allow_site_local and addr_ip.is_site_local:
                return False
        else:
            raise BlacklistException("Unsupported IP version(?): %r" % addr_ip)

        if self.ip_blacklist:
            if any(addr_ip in net for net in self.ip_blacklist):
                return False

        # 169.254.XXX.XXX, AWS uses these for autoconfiguration
        if not self.allow_link_local and addr_ip.is_link_local:
            return False
        # 127.0.0.1, ::1, etc.
        if not self.allow_loopback and addr_ip.is_loopback:
            return False
        if not self.allow_multicast and addr_ip.is_multicast:
            return False
        # 192.168.XXX.XXX, 10.XXX.XXX.XXX
        if not self.allow_private and addr_ip.is_private:
            return False
        # 255.255.255.255, ::ffff:XXXX:XXXX (v6->v4) mapping
        if not self.allow_reserved:
            if addr_ip.is_reserved:
                return False
            # There's no reason to connect directly to a 6to4 relay
            if addr_ip in self._6TO4_RELAY_NET:
                return False

        # 0.0.0.0
        if not self.allow_unspecified and addr_ip.is_unspecified:
            return False

        # It doesn't look bad, so... it's must be ok!
        return True

    def is_addrinfo_allowed(self, addrinfo):
        assert(len(addrinfo) == 5)
        # XXX: Do we care about any of the other elements? Guessing not.
        address = addrinfo[4]

        # The 4th elem inaddrinfo may either be a touple of two or four items,
        # depending on whether we're dealing with IPv4 or v6
        if len(address) == 2:
            # v4
            ip, port = address
        elif len(address) == 4:
            # v6
            # XXX: what *are* `flow_info` and `scope_id`? Anything useful?
            # Seems like we can figure out all we need about the scope from
            # the `is_<x>` properties.
            ip, port, flow_info, scope_id = address
        else:
            raise BlacklistException("Unexpected addrinfo format %r" % address)

        # Probably won't help protect against SSRF, but might prevent our being
        # used to attack others' non-HTTP services. See
        # http://www.remote.org/jochen/sec/hfpa/
        if self.port_whitelist:
            if port not in self.port_whitelist:
                return False
        if self.port_blacklist:
            if port in self.port_blacklist:
                return False

        return self.is_ip_allowed(ip)
