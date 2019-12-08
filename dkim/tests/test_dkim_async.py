# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>

import email
import os.path
import unittest
import time
from dnslib import intercept
# Python 3.5+
import asyncio

import dkim


def read_test_data(filename):
    """Get the content of the given test data file.

    The files live in dkim/tests/data.
    """
    path = os.path.join(os.path.dirname(__file__), 'data', filename)
    with open(path, 'rb') as f:
        return f.read()


class TestSignAndVerify(unittest.TestCase):
    """End-to-end signature and verification tests."""

    def setUp(self):
        self.message = read_test_data("test.message")
        self.message2 = read_test_data("messagedoublefromsigned")
        self.key1024 = read_test_data("1024_testkey.key")

    def dnsfunc(self, domain, timeout=5, port=53):
        _dns_responses = {
          'test._domainkey.example.com.': read_test_data("1024_testkey_wo_markers.pub.txt"),
        }
        return _dns_responses[domain]


    async def interceptor(self, port=53):
        """Hijack DNS for specified domains on specified port"""
        address = '127.0.0.1'
        intercept = []
        interceptor = await intercept.InterceptResolver(address,port,intercept,timeout=2)
        return

    async def do_test(self):
        await self.interceptor()
        for header_algo in (b"simple", b"relaxed"):
            for body_algo in (b"simple", b"relaxed"):
                sig = dkim.sign(
                    self.message, b"test", b"example.com", self.key1024,
                    canonicalize=(header_algo, body_algo))
                # asyncio.run is Python 3.7+
                res = await dkim.verify_async(sig + self.message, port=53)
                self.assertTrue(res)


    async def test_verifies_async(self):
        # A message verifies after being signed.
        asyncio.run(self.do_test())


    async def test_verifies_async_real(self):
        # A message verifies after being signed.
        # asyncio.run is Python 3.7+
        res = asyncio.run(dkim.verify_async(self.message2,port=53))
        self.assertTrue(res)


def test_suite():
    from unittest import TestLoader
    return  TestLoader().loadTestsFromName(__name__)
