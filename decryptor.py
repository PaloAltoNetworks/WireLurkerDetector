#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Decrypting the encrypted C&C traffic in version C of WireLurker. """

__copyright__   = "Copyright (c) 2014, Palo Alto Networks, Inc."
__author__      = "Claud Xiao"


import sys
import base64
try:
    import pyDes
except ImportError:
    print 'ERROR: the script requires pyDes library installed! ' \
          'Please run this command to install it: \n' \
          '# pip install pyDes --allow-external pyDes --allow-unverified pyDes\n'
    sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print 'Usage: %s <encrypted_message>'
        sys.exit(-1)

    original_data = sys.argv[1]

    session_key = '%d' % sum([int(c) for c in original_data[:10]])
    key = session_key + 'dksyel'

    encrypted_data = original_data[10:]

    des_cryptor = pyDes.des(key, pyDes.ECB, padmode=pyDes.PAD_PKCS5)
    plaintext = des_cryptor.decrypt(base64.b64decode(encrypted_data))

    print plaintext


if __name__ == '__main__':
    main()
