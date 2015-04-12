import fnmatch
import re
import six

from .exceptions import BlacklistException
from .packages import ipaddress


def canonicalize_hostname(hostname):
    """Lowercase and punycodify a hostname"""
    # We do the lowercasing after IDNA encoding because we only want to
    # lowercase the *ASCII* chars.
    # TODO: The differences between IDNA2003 and IDNA2008 might be relevant
    # to us, but both specs are damn confusing.
    return six.text_type(hostname.encode("idna").lower(), 'utf-8')


class AdvocateBlacklist(object):
    _6TO4_RELAY_NET = ipaddress.ip_network("192.88.99.0/24")

    def __init__(
            self,
            ip_blacklist=None,
            port_whitelist=None,
            port_blacklist=None,
            hostname_blacklist=None,
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
        self.ip_blacklist = ip_blacklist or set()
        self.port_whitelist = port_whitelist or set()
        self.port_blacklist = port_blacklist or set()
        self.hostname_blacklist = hostname_blacklist or set()
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
        if not isinstance(addr_ip,
                          (ipaddress.IPv4Address, ipaddress.IPv6Address)):
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

    def _hostname_matches_pattern(self, hostname, pattern):
        # If they specified a string, just assume they only want basic globbing.
        # This stops people from not realizing they're dealing in REs and
        # not escaping their periods unless they specifically pass in an RE.
        # This has the added benefit of letting us sanely handle globbed
        # IDNs by default.
        if isinstance(pattern, six.string_types):
            # convert the glob to a punycode glob, then a regex
            pattern = fnmatch.translate(canonicalize_hostname(pattern))

        hostname = canonicalize_hostname(hostname)
        # Down the line the hostname may get treated as a null-terminated string
        # (as with `socket.getaddrinfo`.) Try to account for that.
        no_null_hostname = hostname.split("\x00")[0]

        return (
            re.match(pattern, hostname) or re.match(pattern, no_null_hostname)
        )

    def is_hostname_allowed(self, hostname):
        # Sometimes (like with "external" services that your IP has privileged
        # access to) you might not always know the IP range to blacklist access
        # to, or the `A` record might change without you noticing.
        # For e.x.: `foocorp.external.org`.
        #
        # Another option is doing something like:
        #
        #     for addrinfo in socket.getaddrinfo("foocorp.external.org", 80):
        #         global_blacklist.ip_blacklist.add(ip_address(addrinfo[4][0]))
        #
        # but that's not always a good idea if they're behind a third-party lb.
        for pattern in self.hostname_blacklist:
            if self._hostname_matches_pattern(hostname, pattern):
                return False
        return True

    def is_addrinfo_allowed(self, addrinfo):
        assert(len(addrinfo) == 5)
        # XXX: Do we care about any of the other elements? Guessing not.
        family, socktype, proto, canonname, sockaddr = addrinfo

        # The 4th elem inaddrinfo may either be a touple of two or four items,
        # depending on whether we're dealing with IPv4 or v6
        if len(sockaddr) == 2:
            # v4
            ip, port = sockaddr
        elif len(sockaddr) == 4:
            # v6
            # XXX: what *are* `flow_info` and `scope_id`? Anything useful?
            # Seems like we can figure out all we need about the scope from
            # the `is_<x>` properties.
            ip, port, flow_info, scope_id = sockaddr
        else:
            raise BlacklistException("Unexpected addrinfo format %r" % sockaddr)

        # Probably won't help protect against SSRF, but might prevent our being
        # used to attack others' non-HTTP services. See
        # http://www.remote.org/jochen/sec/hfpa/
        if self.port_whitelist and port not in self.port_whitelist:
            return False
        if port in self.port_blacklist:
            return False

        if self.hostname_blacklist:
            if not canonname:
                raise BlacklistException(
                    "addrinfo must contain the canon name to do blacklisting "
                    "based on hostname. Make sure you use the "
                    "`socket.AI_CANONNAME` flag, and that each record contains "
                    "the canon name. Your DNS server might also be garbage."
                )

            if not self.is_hostname_allowed(canonname):
                return False

        return self.is_ip_allowed(ip)
