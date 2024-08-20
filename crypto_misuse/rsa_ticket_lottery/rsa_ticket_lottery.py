#!/usr/bin/env python3

import os
import os.path
import random
import sys
import argparse
import math
import string

from util import check_challenge
from Cryptodome.PublicKey import RSA

pkfile = 'rsa_key.pub'
skfile = 'rsa_key'


def rsa_kg():
    key = RSA.generate(4096)

    with open(skfile, 'wb') as f:
        f.write(key.exportKey('PEM'))

    pk = key.publickey()

    with open(pkfile, 'wb') as f:
        f.write(pk.exportKey('PEM'))


def rsa_encrypt(fname):
    with open(pkfile, 'rb') as f:
        sk = RSA.importKey(f.read(), 'PEM')

    with open(fname, 'rb') as f:
        pt = f.read()
        pt = int.from_bytes(pt, byteorder="little")

    if pt > sk.n:
        print("Plaintext must be smaller than modulus to allow encryption!")
        sys.exit(-1)

    # Textbook RSA; Cryptodome.Cipher.PKCS1_OAEP for practical RSA (with padding)
    ct = pow(pt, sk.e, sk.n)

    nlen = sk.size_in_bytes()
    ct = ct.to_bytes(nlen, byteorder="little")

    with open(fname + '.enc', 'wb') as f:
        f.write(ct)


def rsa_decrypt(fname):
    with open(skfile, 'rb') as f:
        sk = RSA.importKey(f.read(), 'PEM')

    with open(fname + '.enc', 'rb') as f:
        ct = f.read()
        ct = int.from_bytes(ct, byteorder="little")

    if ct > sk.n:
        print("Ciphertext is invalid (larger than modulus)!")
        sys.exit(-1)

    pt = pow(ct, sk.d, sk.n)
    ptlen = math.ceil(pt.bit_length() / 8)
    pt = pt.to_bytes(ptlen, byteorder="little")

    with open(fname, 'wb') as f:
        f.write(pt)


def solve_challenge(fname):
    with open(fname + '.enc', 'rb') as f:
        ct = f.read()

    with open(pkfile, 'rb') as f:
        pk = RSA.importKey(f.read(), 'PEM')

    pt = bytes()
    
########################################################################
# enter your code here
    c = int.from_bytes(ct, byteorder="little")  # convert given ciphertext bytes to int, so we can calculate with it
    n = pk.n                                    # get n from public key
    e = pk.e                                    # get e from public key

    list_of_possible_sectors = ["A", "B", "C", "D", "E", "F"]
    list_of_possible_tribunes = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"]
    list_of_possible_rows = list(range(0,10))
    list_of_possible_seats = list(range(00,100))

    found_m = False

    # Bruteforce possible m's

    for current_sector in list_of_possible_sectors:
        for current_tribunes in list_of_possible_tribunes:
            for current_rows in list_of_possible_rows:
                for current_seats in list_of_possible_seats:

                    current_m_string = "Congratulations! Your seat destination is in sector " + current_sector + \
                                       " on tribune " + current_tribunes + " at row " + str(current_rows) + \
                                       " with seat " + "{:02d}".format(current_seats)

                    current_m_int = int.from_bytes(bytes(current_m_string, 'utf-8'), byteorder="little")

                    # Textbook RSA; Cryptodome.Cipher.PKCS1_OAEP for practical RSA (with padding)
                    # Determinism. Encrypting the same m twice will lead to the same c
                    current_ct = pow(current_m_int, e, n)

                    # if the generated m match the predicted cipher text
                    if current_ct == c:
                        # we have found m
                        ptlen = math.ceil(current_m_int.bit_length() / 8)
                        m = current_m_int.to_bytes(ptlen, byteorder="little")
                        pt = m
                        found_m = True
                        break
                if found_m:
                    break
            if found_m:
                break
        if found_m:
            break

########################################################################
    
    with open(fname, 'wb') as f:
        f.write(pt)
        return


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', title='subcommand')
    subparsers.required = True
    parser_e = subparsers.add_parser('e', help='encrypt')
    parser_e.add_argument('file')
    parser_d = subparsers.add_parser('d', help='decrypt')
    parser_d.add_argument('file')
    parser_g = subparsers.add_parser('g', help='keygen')
    parser_c = subparsers.add_parser('c', help='challenge')
    parser_c.add_argument(
        'file',
        nargs='?',
        default='challenge.enc',
        help='default: challenge.enc')
    args = parser.parse_args()

    if args.command == 'g':
        rsa_kg()
        return

    fname = args.file
    if not os.path.isfile(fname):
        print('no valid file specified')
        return -1

    if args.command == 'e':
        if not (os.path.isfile(pkfile)):
            print('no public key found, run key generation first!')
            return -1
        rsa_encrypt(fname)
        return

    if args.command == 'd':
        if not (os.path.isfile(pkfile)):
            print('no private key found, run key generation first!')
            return -1
        rsa_decrypt(fname[:-4])
        return

    if args.command == 'c':
        if not (os.path.isfile(pkfile)):
            print('no public key found, restore original public key first!')
            return -1
        solve_challenge(fname[:-4])
        check_challenge(fname[:-4])
        return


if __name__ == "__main__":
    sys.exit(main())
