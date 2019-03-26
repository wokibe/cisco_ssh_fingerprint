#!/usr/bin/env python3

__description__ = 'Calculate the SSH fingerprint from a Cisco public key dumped with command "show crypto key mypubkey rsa"'
__author__ = 'Didier Stevens  & wolfkibe@gmail.com'
__version__ = '0.0.3'
__date__ = '2019/03/26'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2011/12/20: start
  2014/08/19: fixed bug MatchLength
  2019/03/26: reengineered for python 3
              calculate base64 encoded SHA256 
Todo:
"""

import argparse
import struct
import hashlib
import base64
import sys
import platform

def hex2(byt):
    """format a byte in a 2 character hex string"""
    str = hex(byt)[2:]          # strip the 0x
    if len(str) == 1:
        str = '0' + str
    return str.upper()

def DumpData(data):
    """Compact dump of data byte list"""
    lst = ''
    for x in data:
        lst += hex2(x) + ' '
    print(lst)

def IsHexDigit(string):
    if string == '':
        return False
    for char in string:
        if not (char.isdigit() or char.lower() >= 'a' and char.lower() <= 'f'):
            return False
    return True

def HexDumpFile2Data(filename):
    """convert the Cisco dump bytes to a list of integers"""
    global finger
    debug = finger['debug']
    
    if debug:
        print('Filename: {}'.format(filename))

    if filename:
        try:
            f = open(filename, 'r')
        except:
            return None
    else:
        # as no filename defined, we allow input via STDIN
        if platform.system() == 'Windows':
            eof = 'CTRL-Z'
        else:
            eof = 'CTRL-D'
        print('Paste the Cisco key dump and terminate with {}'.format(eof))
        f = sys.stdin

    hex = f.read()
    if debug:
        print('raw input:')
        print(hex)
    hex = hex.replace('\n','').replace(' ','')
    if debug:
        print('cleaned input:')
        print(hex)

    if filename:
        f.close()

    if not IsHexDigit(hex):
        return None
    if len(hex) % 2 != 0:
        return None

    # combine odd and even chars into bytes
    return list(map(lambda x, y: int(x+y, 16), hex[::2], hex[1::2]))

def MatchByte(byte, data):
    if len(data) < 1:
        return (data, False)
    if data[0] != byte:
        return (data, False)
    return (data[1:], True)

def MatchLength(data):
    if len(data) < 1:
        return (data, False, 0)
    if data[0] <= 0x80: #a# check 80
        return (data[1:], True, data[0])
    countBytes = data[0] - 0x80
    data = data[1:]
    if len(data) < countBytes:
        return (data, False, 0)
    length = 0
    for index in range(0, countBytes):
        length = data[index] + length * 0x100
    return (data[countBytes:], True, length)

def MatchString(string, data):
    if len(data) < len(string):
        return (data, False)
    if data[:len(string)] != string:
        return (data, False)
    return (data[len(string):], True)

def ParsePublicKeyDER(data):
    data, match = MatchByte(0x30, data)
    if not match:
        print('Parse error: expected sequence (0x30)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 1: %d' % length)
        return None

    str = [0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,
           0x01,0x01,0x01,0x05,0x00]
    data, match = MatchString(str, data)
    if not match:
        print('Parse error: expected OID rsaEncryption')
        return None

    data, match = MatchByte(0x03, data)
    if not match:
        print('Parse error: expected bitstring (0x03)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 2: %d' % length)
        return None

    data, match = MatchByte(0x00, data)
    if not match:
        print('Parse error: expected no padding (0x00)')
        return None

    data, match = MatchByte(0x30, data)
    if not match:
        print('Parse error: expected sequence (0x30)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 3: %d' % length)
        return None

    data, match = MatchByte(0x02, data)
    if not match:
        print('Parse error: expected integer (0x02)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 4: %d' % length)
        return None
    modulus = data[:length]
    data = data[length:]

    data, match = MatchByte(0x02, data)
    if not match:
        print('Parse error: expected integer (0x02)')
        return None

    data, match, length = MatchLength(data)
    if not match:
        print('Parse error: expected length')
        return None
    if length > len(data):
        print('Parse error: incomplete DER encoded key 5: %d' % length)
        return None
    exponent = data[:length]

    return (modulus, exponent)

def LengthEncode(data):
    return struct.pack('>I', len(data)) + data

def CalcFingerprint(modulus, exponent):
    global finger
    debug = finger['debug']

    data = b"".join([LengthEncode('ssh-rsa'.encode()),
        LengthEncode(bytes(exponent)),
        LengthEncode(bytes(modulus))])
    if debug:
        print ('ssh-rsa prepared input:')
        DumpData(data)
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).digest()
    return md5, sha256


def CiscoCalculateSSHFingerprint(filename):
    global finger
    debug = finger['debug']

    publicKeyDER = HexDumpFile2Data(filename)
    if publicKeyDER == None:
        print('Error reading public key')
        return

    if debug:
        print ('formatted input:')
        DumpData(publicKeyDER)
    result = ParsePublicKeyDER(publicKeyDER)
    if result == None:
        return

    if debug:
        print('modulus:')
        DumpData(result[0])
        print('exponent:')
        DumpData(result[1])

#    fingerprint = CalcFingerprint(result[0], result[1])
    md5, sha256 = CalcFingerprint(result[0], result[1])
    print('MD5:    {}'.format(md5))
    print('SHA256: {}'.format(base64.b64encode(sha256).decode()))

def Main():
    # verify Python3
    if sys.version_info[0] < 3:
        print('Sorry, this script needs Python3')
        sys.exit()

    # arguments handling
    parser = argparse.ArgumentParser(description=
        'Calculate the fingerprint of a Cisco crypto public rsa key')
    parser.add_argument('--filename', '-f', help=
        'dump part of Cisco output "show crypto key mypubkey rsa"')
    parser.add_argument('--debug', '-d', help= 'development support',
        action='store_true')
    args = parser.parse_args()

    # save dictionary of arguments in a global variable
    global finger
    finger = vars(args)

    # go for it
    CiscoCalculateSSHFingerprint(args.filename)

if __name__ == '__main__':
    Main()
