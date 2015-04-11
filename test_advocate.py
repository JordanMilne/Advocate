# coding=utf-8

from __future__ import print_function

import unittest

import advocate
from advocate import AdvocateBlacklist
from advocate.connection import advocate_getaddrinfo
from advocate.exceptions import UnacceptableAddressException

try:
    import ipaddress
except ImportError:
    from advocate.packages import ipaddress


def permissive_blacklist(**kwargs):
    """Create an AdvocateBlacklist that allows everything by default"""
    default_options = dict(
        ip_blacklist=None,
        port_whitelist=None,
        port_blacklist=None,
        hostname_blacklist=None,
        allow_ipv6=True,
        allow_teredo=True,
        allow_6to4=True,
        allow_link_local=True,
        allow_loopback=True,
        allow_multicast=True,
        allow_private=True,
        allow_reserved=True,
        allow_site_local=True,
        allow_unspecified=True,
    )
    default_options.update(**kwargs)
    return AdvocateBlacklist(**default_options)


class BlackListIPTests(unittest.TestCase):
    def _test_ip_kind_blocked(self, ip, **kwargs):
        bl = permissive_blacklist(**kwargs)
        self.assertFalse(bl.is_ip_allowed(ip))

    def test_manual_ip_blacklist(self):
        """Test manually blacklisting based on IP"""
        bl = AdvocateBlacklist(
            allow_ipv6=True,
            ip_blacklist=(
                ipaddress.ip_network("132.0.5.0/24"),
                ipaddress.ip_network("152.0.0.0/8"),
                ipaddress.ip_network("::1"),
            ),
        )
        self.assertFalse(bl.is_ip_allowed("132.0.5.1"))
        self.assertFalse(bl.is_ip_allowed("152.254.90.1"))
        self.assertTrue(bl.is_ip_allowed("178.254.90.1"))
        self.assertFalse(bl.is_ip_allowed("::1"))
        # Google, found via `dig google.com AAAA`
        self.assertTrue(bl.is_ip_allowed("2607:f8b0:400a:807::200e"))

    @unittest.skip("takes half an hour or so to run")
    def test_safecurl_blacklist(self):
        """Test that we at least disallow everything SafeCurl does"""
        # All IPs that SafeCurl would disallow
        bad_netblocks = (ipaddress.ip_network(x) for x in (
            '0.0.0.0/8',
            '10.0.0.0/8',
            '100.64.0.0/10',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '172.16.0.0/12',
            '192.0.0.0/29',
            '192.0.2.0/24',
            '192.88.99.0/24',
            '192.168.0.0/16',
            '198.18.0.0/15',
            '198.51.100.0/24',
            '203.0.113.0/24',
            '224.0.0.0/4',
            '240.0.0.0/4'
        ))
        i = 0
        bl = AdvocateBlacklist()
        for bad_netblock in bad_netblocks:
            num_ips = bad_netblock.num_addresses
            # Don't test *every* IP in large netblocks
            step_size = int(min(max(num_ips / 255, 1), 128))
            for ip_idx in xrange(0, num_ips, step_size):
                i += 1
                bad_ip = bad_netblock[ip_idx]
                thing = bl.is_ip_allowed(bad_ip)
                if thing or True:
                    print(i, bad_ip)
                self.assertFalse(thing)

    # TODO: something like the above for IPv6?

    def test_ipv4_mapped(self):
        self._test_ip_kind_blocked("::ffff:192.168.2.1", allow_private=False)

    def test_teredo(self):
        # 192.168.2.1 as the client address
        self._test_ip_kind_blocked(
            "2001:0000:4136:e378:8000:63bf:3f57:fdf2",
            allow_private=False
        )
        # This should also be disallowed if teredo is completely disallowed.
        self._test_ip_kind_blocked(
            "2001:0000:4136:e378:8000:63bf:3f57:fdf2",
            allow_teredo=False,
        )

    def test_ipv6(self):
        self._test_ip_kind_blocked("2002:C0A8:FFFF::", allow_ipv6=False)

    def test_sixtofour(self):
        # 192.168.XXX.XXX
        self._test_ip_kind_blocked("2002:C0A8:FFFF::", allow_private=False)
        self._test_ip_kind_blocked("2002:C0A8:FFFF::", allow_6to4=False)

    @unittest.expectedFailure
    def test_dns64(self):
        # XXX: Don't even know if this is an issue, TBH. Seems to be related
        # to DNS64/NAT64, but not a lot of easy-to-understand info:
        # https://tools.ietf.org/html/rfc6052
        self._test_ip_kind_blocked("64:ff9b::192.168.2.1", allow_private=False)

    def test_link_local(self):
        # 169.254.XXX.XXX, AWS uses these for autoconfiguration
        self._test_ip_kind_blocked("169.254.1.1", allow_link_local=False)

    def test_site_local(self):
        self._test_ip_kind_blocked("FEC0:CCCC::", allow_site_local=False)

    def test_loopback(self):
        self._test_ip_kind_blocked("127.0.0.1", allow_loopback=False)
        self._test_ip_kind_blocked("::1", allow_loopback=False)

    def test_multicast(self):
        self._test_ip_kind_blocked("227.1.1.1", allow_multicast=False)

    def test_private(self):
        self._test_ip_kind_blocked("192.168.2.1", allow_private=False)
        self._test_ip_kind_blocked("10.5.5.5", allow_private=False)
        self._test_ip_kind_blocked("0.0.0.0", allow_private=False)
        self._test_ip_kind_blocked("0.1.1.1", allow_private=False)
        self._test_ip_kind_blocked("100.64.0.0", allow_private=False)

    def test_reserved(self):
        self._test_ip_kind_blocked("255.255.255.255", allow_reserved=False)
        self._test_ip_kind_blocked("::ffff:192.168.2.1", allow_reserved=False)
        # 6to4 relay
        self._test_ip_kind_blocked("192.88.99.0", allow_reserved=False)

    def test_unspecified(self):
        self._test_ip_kind_blocked("0.0.0.0", allow_unspecified=False)


class AddrInfoTests(unittest.TestCase):
    def _is_addrinfo_allowed(self, host, port, **kwargs):
        bl = permissive_blacklist(**kwargs)
        allowed = False
        for res in advocate_getaddrinfo(host, port):
            if bl.is_addrinfo_allowed(res):
                allowed = True
        return allowed

    def test_simple(self):
        self.assertFalse(
            self._is_addrinfo_allowed("192.168.0.1", 80, allow_private=False)
        )

    def test_malformed_addrinfo(self):
        # Alright, the addrinfo format is probably never going to change,
        # but *what if it did?*
        bl = permissive_blacklist()
        addrinfo = advocate_getaddrinfo("example.com", 80)[0] + (1,)
        self.assertRaises(Exception, lambda: bl.is_addrinfo_allowed(addrinfo))

    def test_unexpected_proto(self):
        # What if addrinfo returns info about a protocol we don't understand?
        bl = permissive_blacklist()
        addrinfo = list(advocate_getaddrinfo("example.com", 80)[0])
        addrinfo[4] = addrinfo[4] + (1,)
        self.assertRaises(Exception, lambda: bl.is_addrinfo_allowed(addrinfo))

    def test_port_whitelist(self):
        wl = (80, 10)
        self.assertTrue(
            self._is_addrinfo_allowed("192.168.0.1", 80, port_whitelist=wl)
        )
        self.assertTrue(
            self._is_addrinfo_allowed("::1", 10, port_whitelist=wl)
        )
        self.assertFalse(
            self._is_addrinfo_allowed("192.168.0.1", 99, port_whitelist=wl)
        )

    def test_port_blacklist(self):
        bl = (80, 10)
        self.assertFalse(
            self._is_addrinfo_allowed("192.168.0.1", 80, port_blacklist=bl)
        )
        self.assertFalse(
            self._is_addrinfo_allowed("::1", 10, port_blacklist=bl)
        )
        self.assertTrue(
            self._is_addrinfo_allowed("192.168.0.1", 99, port_blacklist=bl)
        )


class HostnameTests(unittest.TestCase):
    def _is_hostname_allowed(self, host, **kwargs):
        bl = permissive_blacklist(**kwargs)
        addrinfo_allowed = False
        for res in advocate_getaddrinfo(host, 80):
            if bl.is_addrinfo_allowed(res):
                return True
        return False

    def test_no_blacklist(self):
        self.assertTrue(self._is_hostname_allowed("example.com"))

    def test_idn(self):
        # test some basic globs
        self.assertFalse(self._is_hostname_allowed(
            u"中国.icom.museum",
            hostname_blacklist={"*.museum"}
        ))
        # case insensitive, please
        self.assertFalse(self._is_hostname_allowed(
            u"中国.icom.museum",
            hostname_blacklist={"*.Museum"}
        ))
        # we should match both the punycoded domain
        self.assertFalse(self._is_hostname_allowed(
            u"中国.icom.museum",
            hostname_blacklist={"xn--fiqs8s.*.museum"}
        ))
        # and the localized domain
        self.assertFalse(self._is_hostname_allowed(
            u"中国.icom.museum",
            hostname_blacklist={u"中国.*.museum"}
        ))
        self.assertTrue(self._is_hostname_allowed(
            u"example.com",
            hostname_blacklist={u"中国.*.museum"}
        ))


class AdvocateWrapperTests(unittest.TestCase):
    def test_get(self):
        self.assertEqual(advocate.get("http://example.com").status_code, 200)
        self.assertEqual(advocate.get("https://example.com").status_code, 200)

    def test_blacklist(self):
        self.assertRaises(
            UnacceptableAddressException,
            advocate.get, "http://127.0.0.1/"
        )
        self.assertRaises(
            UnacceptableAddressException,
            advocate.get, "http://localhost/"
        )
        self.assertRaises(
            UnacceptableAddressException,
            advocate.get, "https://localhost/"
        )

    def test_redirect(self):
        # Make sure httpbin even works
        test_url = "http://httpbin.org/status/204"
        self.assertEqual(advocate.get(test_url).status_code, 204)

        redir_url = "http://httpbin.org/redirect-to?url=http://127.0.0.1/"
        self.assertRaises(
            UnacceptableAddressException,
            advocate.get, redir_url
        )

if __name__ == '__main__':
    unittest.main()
