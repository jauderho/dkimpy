#!/usr/bin/env python

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
# Copyright (c) 2008 Greg Hewgill http://hewgill.com
#
# This has been modified from the original software.
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>

from __future__ import print_function

import sys
import argparse

import dkim

def filedns(datafile, tgtdomain, selector):

    def dnsf(self, domain, timeout=5):
        target = "{0}._domainkey.{1}.".format(selector, tgtdomain)
        _dns_responses = {
          target : read_test_data(datafile),
        }
        try:
            domain = domain.decode('ascii')
        except UnicodeDecodeError:
            return None
        self.assertTrue(domain in _dns_responses,domain)
        return _dns_responses[domain]

    return dnsf

def main():
    parser = argparse.ArgumentParser(
        description='Verify DKIM signature for email messages.',
        epilog="message to be verified follows commands on stdin")
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
        help='turn verbose mode on')
    parser.add_argument('--index', metavar='N', type=int, default=0,
        help='Index of DKIM signature header to verify: default=0')
    parser.add_argument('-f', '--dnsfile', action="store", default=None,
        help='File containing DKIM public key records' )
    parser.add_argument('-d', '--domain', action="store", default=None,
        help='Domain for DNS record in dnsfile.  Mandatory with -f.' )
    parser.add_argument('-s', '--selector', action="store", default=None,
        help='Selector for DNS record in dnsfile.  Mandatory with -f.' )
    args=parser.parse_args()
    if sys.version_info[0] >= 3:
        # Make sys.stdin a binary stream.
        sys.stdin = sys.stdin.detach()

    message = sys.stdin.read()
    if args.verbose:
        import logging
        log=logging
    else:
        log=None
    if args.dnsfile:
        if not args.domain or not args.selector:
            raise SyntaxError('Both --domain and --selector are required with --dnsfile')
        dnsfc=filedns(args.dnsfile, args.domain, args.selector)
        d = dkim.DKIM(message, logger=log, dnsfunc=dnsfc)
    else:
        d = dkim.DKIM(message, logger=log)
    res = d.verify(args.index)
    if not res:
        print("signature verification failed")
        sys.exit(1)
    print("signature ok")


if __name__ == "__main__":
    main()
