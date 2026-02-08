import unittest

from OhShINT.models.ioc import (
    IOC,
    MD5,
    SHA1,
    SHA256,
    Domain,
    IPv4,
    IPv6,
    get_ioc_type,
    ioc_regex_search,
    is_domain,
    is_ipv4,
    is_ipv6,
    is_md5,
    is_public_ip,
    is_sha1,
    is_sha256,
)


class TestIPValidation(unittest.TestCase):
    """Test IP address validation functions"""

    def test_is_ipv4_valid(self):
        """Test valid IPv4 addresses"""
        self.assertTrue(is_ipv4("192.168.1.1"))
        self.assertTrue(is_ipv4("8.8.8.8"))
        self.assertTrue(is_ipv4("10.0.0.1"))
        self.assertTrue(is_ipv4("172.16.0.1"))
        self.assertTrue(is_ipv4("255.255.255.255"))
        self.assertTrue(is_ipv4("0.0.0.0"))

    def test_is_ipv4_invalid(self):
        """Test invalid IPv4 addresses"""
        self.assertFalse(is_ipv4("256.1.1.1"))
        self.assertFalse(is_ipv4("192.168.1"))
        self.assertFalse(is_ipv4("192.168.1.1.1"))
        self.assertFalse(is_ipv4("not.an.ip.address"))
        self.assertFalse(is_ipv4(""))
        self.assertFalse(is_ipv4("2001:0db8:85a3::8a2e:0370:7334"))

    def test_is_ipv6_valid(self):
        """Test valid IPv6 addresses"""
        self.assertTrue(is_ipv6("2001:0db8:85a3::8a2e:0370:7334"))
        self.assertTrue(is_ipv6("2001:db8::1"))
        self.assertTrue(is_ipv6("::1"))
        self.assertTrue(is_ipv6("fe80::"))
        self.assertTrue(is_ipv6("::"))

    def test_is_ipv6_invalid(self):
        """Test invalid IPv6 addresses"""
        self.assertFalse(is_ipv6("192.168.1.1"))
        self.assertFalse(is_ipv6("not:an:ipv6:address"))
        self.assertFalse(is_ipv6(""))
        self.assertFalse(is_ipv6("gggg::1"))

    def test_is_public_ip_public_ipv4(self):
        """Test public IPv4 addresses"""
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertTrue(is_public_ip("1.1.1.1"))
        self.assertTrue(is_public_ip("142.250.185.46"))

    def test_is_public_ip_private_ipv4(self):
        """Test private IPv4 addresses"""
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("172.16.0.1"))
        self.assertFalse(is_public_ip("127.0.0.1"))

    def test_is_public_ip_public_ipv6(self):
        """Test public IPv6 addresses"""
        self.assertTrue(is_public_ip("2001:4860:4860::8888"))

    def test_is_public_ip_private_ipv6(self):
        """Test private IPv6 addresses"""
        self.assertFalse(is_public_ip("::1"))
        self.assertFalse(is_public_ip("fe80::1"))

    def test_is_public_ip_invalid(self):
        """Test invalid IP addresses"""
        self.assertFalse(is_public_ip("not.an.ip"))
        self.assertFalse(is_public_ip(""))


class TestDomainValidation(unittest.TestCase):
    """Test domain validation functions"""

    def test_is_domain_valid(self):
        """Test valid domain names"""
        self.assertTrue(is_domain("example.com"))
        self.assertTrue(is_domain("subdomain.example.com"))
        self.assertTrue(is_domain("sub.domain.example.co.uk"))
        self.assertTrue(is_domain("test-domain.com"))

    def test_is_domain_invalid(self):
        """Test invalid domain names"""
        self.assertFalse(is_domain("a.b"))
        self.assertFalse(is_domain("192.168.1.1"))
        self.assertFalse(is_domain("nodot"))
        self.assertFalse(is_domain(""))
        self.assertFalse(is_domain("123.456"))


class TestHashValidation(unittest.TestCase):
    """Test hash validation functions"""

    def test_is_md5_valid(self):
        """Test valid MD5 hashes"""
        self.assertTrue(is_md5("d41d8cd98f00b204e9800998ecf8427e"))
        self.assertTrue(is_md5("5d41402abc4b2a76b9719d911017c592"))
        self.assertTrue(is_md5("a" * 32))

    def test_is_md5_invalid(self):
        """Test invalid MD5 hashes"""
        self.assertFalse(is_md5("short"))
        self.assertFalse(is_md5("a" * 31))
        self.assertFalse(is_md5("a" * 33))
        self.assertFalse(is_md5(""))

    def test_is_sha1_valid(self):
        """Test valid SHA1 hashes"""
        self.assertTrue(is_sha1("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
        self.assertTrue(is_sha1("356a192b7913b04c54574d18c28d46e6395428ab"))
        self.assertTrue(is_sha1("a" * 40))

    def test_is_sha1_invalid(self):
        """Test invalid SHA1 hashes"""
        self.assertFalse(is_sha1("short"))
        self.assertFalse(is_sha1("a" * 39))
        self.assertFalse(is_sha1("a" * 41))
        self.assertFalse(is_sha1(""))

    def test_is_sha256_valid(self):
        """Test valid SHA256 hashes"""
        self.assertTrue(
            is_sha256(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
        )
        self.assertTrue(is_sha256("a" * 64))

    def test_is_sha256_invalid(self):
        """Test invalid SHA256 hashes"""
        self.assertFalse(is_sha256("short"))
        self.assertFalse(is_sha256("a" * 63))
        self.assertFalse(is_sha256("a" * 65))
        self.assertFalse(is_sha256(""))


class TestIOCRegexSearch(unittest.TestCase):
    """Test IOC regex search function"""

    def test_ioc_regex_search_ip(self):
        """Test searching for IP addresses"""
        content = "Found IPs: 192.168.1.1 and 8.8.8.8"
        results = ioc_regex_search("192.168.1.1", content)
        self.assertEqual(len(results), 2)
        self.assertIn("192.168.1.1", results)
        self.assertIn("8.8.8.8", results)

    def test_ioc_regex_search_with_ioc_instance(self):
        """Test searching with IOC instance"""
        content = "IP: 192.168.1.1"
        ioc = IOC("192.168.1.1")
        results = ioc_regex_search(ioc, content)
        self.assertEqual(len(results), 1)
        self.assertIn("192.168.1.1", results)

    def test_ioc_regex_search_domain(self):
        """Test searching for domains"""
        content = "Visit example.com and subdomain.test.org"
        results = ioc_regex_search("example.com", content)
        self.assertEqual(len(results), 2)
        self.assertIn("example.com", results)
        self.assertIn("subdomain.test.org", results)

    def test_ioc_regex_search_sha256(self):
        """Test searching for SHA256 hashes"""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        content = f"Hash: {sha256_hash}"
        results = ioc_regex_search(sha256_hash, content)
        self.assertEqual(len(results), 1)
        self.assertIn(sha256_hash, results)

    def test_ioc_regex_search_sha1(self):
        """Test searching for SHA1 hashes"""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        content = f"Hash: {sha1_hash}"
        results = ioc_regex_search(sha1_hash, content)
        self.assertEqual(len(results), 1)
        self.assertIn(sha1_hash, results)

    def test_ioc_regex_search_md5(self):
        """Test searching for MD5 hashes"""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        content = f"Hash: {md5_hash}"
        results = ioc_regex_search(md5_hash, content)
        self.assertEqual(len(results), 1)
        self.assertIn(md5_hash, results)

    def test_ioc_regex_search_no_matches(self):
        """Test searching with no matches"""
        content = "No IOCs here"
        with self.assertRaises(ValueError) as context:
            ioc_regex_search("8.8.8.8", content)
        self.assertIn("matches found", str(context.exception))

    def test_ioc_regex_search_invalid_type(self):
        """Test searching with invalid IOC value"""
        content = "Some content"
        with self.assertRaises(ValueError) as context:
            ioc_regex_search("not_a_valid_ioc", content)
        self.assertIn("Could not determine IOC type", str(context.exception))


class TestGetIOCType(unittest.TestCase):
    """Test IOC type detection"""

    def test_get_ioc_type_ipv4(self):
        """Test IPv4 detection"""
        ioc_type = get_ioc_type("8.8.8.8")
        self.assertEqual(ioc_type, IPv4)

    def test_get_ioc_type_ipv6(self):
        """Test IPv6 detection"""
        ioc_type = get_ioc_type("2001:4860:4860::8888")
        self.assertEqual(ioc_type, IPv6)

    def test_get_ioc_type_domain(self):
        """Test domain detection"""
        ioc_type = get_ioc_type("example.com")
        self.assertEqual(ioc_type, Domain)

    def test_get_ioc_type_md5(self):
        """Test MD5 detection"""
        ioc_type = get_ioc_type("d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(ioc_type, MD5)

    def test_get_ioc_type_sha1(self):
        """Test SHA1 detection"""
        ioc_type = get_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(ioc_type, SHA1)

    def test_get_ioc_type_sha256(self):
        """Test SHA256 detection"""
        ioc_type = get_ioc_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        self.assertEqual(ioc_type, SHA256)

    def test_get_ioc_type_no_type_detected(self):
        """Test with no valid IOC type"""
        with self.assertRaises(ValueError) as context:
            get_ioc_type("not_an_ioc")
        self.assertIn("Could not determine IOC type", str(context.exception))

    def test_get_ioc_type_private_ip(self):
        """Test with private IP (should log error but still return type)"""
        # Private IPs still return a type, just log an error
        ioc_type = get_ioc_type("192.168.1.1")
        self.assertEqual(ioc_type, IPv4)


class TestIOCFactory(unittest.TestCase):
    """Test IOC factory pattern and classes"""

    def test_ioc_creates_ipv4(self):
        """Test IOC factory creates IPv4 instance"""
        ioc = IOC("8.8.8.8")
        self.assertIsInstance(ioc, IPv4)
        self.assertEqual(ioc.value, "8.8.8.8")
        self.assertEqual(ioc.cn, "IPv4")
        self.assertEqual(str(ioc), "8.8.8.8")

    def test_ioc_creates_ipv6(self):
        """Test IOC factory creates IPv6 instance"""
        ioc = IOC("2001:4860:4860::8888")
        self.assertIsInstance(ioc, IPv6)
        self.assertEqual(ioc.value, "2001:4860:4860::8888")
        self.assertEqual(ioc.cn, "IPv6")

    def test_ioc_creates_domain(self):
        """Test IOC factory creates Domain instance"""
        ioc = IOC("example.com")
        self.assertIsInstance(ioc, Domain)
        self.assertEqual(ioc.value, "example.com")
        self.assertEqual(ioc.cn, "Domain")

    def test_ioc_creates_md5(self):
        """Test IOC factory creates MD5 instance"""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        ioc = IOC(md5_hash)
        self.assertIsInstance(ioc, MD5)
        self.assertEqual(ioc.value, md5_hash)
        self.assertEqual(ioc.cn, "MD5")

    def test_ioc_creates_sha1(self):
        """Test IOC factory creates SHA1 instance"""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ioc = IOC(sha1_hash)
        self.assertIsInstance(ioc, SHA1)
        self.assertEqual(ioc.value, sha1_hash)
        self.assertEqual(ioc.cn, "SHA1")

    def test_ioc_creates_sha256(self):
        """Test IOC factory creates SHA256 instance"""
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ioc = IOC(sha256_hash)
        self.assertIsInstance(ioc, SHA256)
        self.assertEqual(ioc.value, sha256_hash)
        self.assertEqual(ioc.cn, "SHA256")

    def test_ioc_invalid_raises_error(self):
        """Test IOC factory raises error for invalid input"""
        with self.assertRaises(ValueError):
            IOC("not_a_valid_ioc")

    def test_ioc_str_representation(self):
        """Test string representation of IOC"""
        ioc = IOC("8.8.8.8")
        self.assertEqual(str(ioc), "8.8.8.8")

    def test_ioc_class_name_property(self):
        """Test class name property (cn) of IOC subclasses"""
        ipv4 = IOC("8.8.8.8")
        self.assertEqual(ipv4.cn, "IPv4")

        domain = IOC("example.com")
        self.assertEqual(domain.cn, "Domain")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions"""

    def test_empty_string_handling(self):
        """Test handling of empty strings"""
        self.assertFalse(is_ipv4(""))
        self.assertFalse(is_ipv6(""))
        self.assertFalse(is_domain(""))

    def test_whitespace_handling(self):
        """Test handling of whitespace"""
        self.assertFalse(is_ipv4("   "))
        self.assertFalse(is_domain("   "))

    def test_boundary_ip_addresses(self):
        """Test boundary IP addresses"""
        self.assertTrue(is_ipv4("0.0.0.0"))
        self.assertTrue(is_ipv4("255.255.255.255"))

    def test_hash_with_uppercase(self):
        """Test hashes with uppercase letters"""
        self.assertTrue(is_md5("D41D8CD98F00B204E9800998ECF8427E"))
        self.assertTrue(is_sha1("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"))
        self.assertTrue(
            is_sha256(
                "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
            )
        )

    def test_mixed_case_hash(self):
        """Test hashes with mixed case"""
        self.assertTrue(is_md5("D41d8cD98f00b204e9800998ecf8427e"))
