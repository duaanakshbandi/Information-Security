#!/usr/bin/env python3

import sys
import argparse
from util import check_challenge
from Cryptodome.Hash import SHA512
import random
import getpass
import string
from math import prod

PASSWORD_LENGTH = 13
PASSWORD_ALPHABET = string.ascii_letters + string.digits + string.punctuation

def generate_password():
    password = ""
    # We use a great source of randomness!
    random_source = random.SystemRandom()
    for _ in range(PASSWORD_LENGTH):
        index = int(prod(random_source.random() for _ in range(8)) * len(PASSWORD_ALPHABET) + 33) * 567 % len(PASSWORD_ALPHABET)
        password += PASSWORD_ALPHABET[index]

    return password


def verify(password, password_hash):
    assert type(password) == str and "password has to be of type string!"

    hasher = SHA512.new()
    hasher.update(password.encode('utf-8'))
    computed_hash = hasher.hexdigest()

    if computed_hash == password_hash:
        return True
    else:
        return False

def solve_challenge(challenge_hash_file):

    with open(challenge_hash_file, 'r') as f:
        password_hash = f.read()

    password = "0" * PASSWORD_LENGTH

    ########################################################
    # enter your code here
    # On average, there will be 11,82 "f" characters in our password
    password = "f" * PASSWORD_LENGTH
    found = 0

    # Passwords with 1 character not being "f"
    for index1 in range(0, PASSWORD_LENGTH):
        for v1 in PASSWORD_ALPHABET:
            password = "f" * PASSWORD_LENGTH
            password = password[:index1] + v1 + password[index1 + 1:]
            if (verify(password, password_hash)):
                found = 1
                break
        if (found):
            break

    # Passwords with 2 characters not being "f"
    if (not found):
        for index1 in range(0, PASSWORD_LENGTH):
            for v1 in ['i', 'l', 'o', 'r', 'u', 'x', 'A', 'D', 'G', 'J', 'M', 'P', 'S', 'V', 'Y', '1', '4', '7']:
                for index2 in range(0, PASSWORD_LENGTH):
                    for v2 in ['i', 'l', 'o', 'r', 'u', 'x', 'A', 'D', 'G', 'J', 'M', 'P', 'S', 'V', 'Y', '1', '4', '7']:
                        password = "f" * PASSWORD_LENGTH
                        password = password[:index2] + v2 + password[index2 + 1:]
                        password = password[:index1] + v1 + password[index1 + 1:]
                        if (verify(password, password_hash)):
                            found = 1
                            break
                    if (found):
                        break
                if (found):
                    break
            if (found):
                break

    # Passwords with 3 characters not being "f"
    if (not found):
        for index1 in range(0, PASSWORD_LENGTH):
            for v1 in ['i', 'l', 'o', 'r', 'u', 'x', 'A', 'D', 'G', 'J']:
                for index2 in range(0, PASSWORD_LENGTH):
                    for v2 in ['i', 'l', 'o', 'r', 'u']:
                        for index3 in range(0, PASSWORD_LENGTH):
                            for v3 in ['i', 'l', 'o']:
                                password = "f" * PASSWORD_LENGTH
                                password = password[:index3] + v3 + password[index3 + 1:]
                                password = password[:index2] + v2 + password[index2 + 1:]
                                password = password[:index1] + v1 + password[index1 + 1:]
                                if (verify(password, password_hash)):
                                    found = 1
                                    break
                            if (found):
                                break
                        if (found):
                            break
                    if (found):
                        break
                if (found):
                    break
            if (found):
                break

    # Passwords with 4 characters not being "f"
    if (not found):
        for index1 in range(0, PASSWORD_LENGTH):
            for v1 in ['i', 'l', 'o', 'r', 'u', 'x']:
                for index2 in range(0, PASSWORD_LENGTH):
                    for v2 in ['i', 'l', 'o']:
                        for index3 in range(0, PASSWORD_LENGTH):
                            for v3 in ['i', 'l']:
                                for index4 in range(0, PASSWORD_LENGTH):
                                    for v4 in ['i', 'l']:
                                        password = "f" * PASSWORD_LENGTH
                                        password = password[:index4] + v4 + password[index4 + 1:]
                                        password = password[:index3] + v3 + password[index3 + 1:]
                                        password = password[:index2] + v2 + password[index2 + 1:]
                                        password = password[:index1] + v1 + password[index1 + 1:]
                                        if (verify(password, password_hash)):
                                            found = 1
                                            break
                                    if (found):
                                        break
                                if (found):
                                    break
                            if (found):
                                break
                        if (found):
                            break
                    if (found):
                        break
                if (found):
                    break
            if (found):
                break

    # There is no way we need to crack pws with 5 chars or more not being "f" right? SURELY NOT RIGHT?!

    #weighted = {'f': 260211024, 'i': 13581764, 'l': 5157400, 'o': 2571776, 'r': 1466551, 'u': 906220, 'x': 590751, 'A': 401384, 'D': 280919, 'G': 201528, 'J': 146854, 'M': 108844, 'P': 82252, 'S': 62584, 'V': 48460, 'Y': 37447, '1': 29682, '4': 22785, '7': 17889, '!': 14360, '$': 11594, "'": 9240, '*': 7337, '-': 6014, ':': 4803, '=': 3913, '@': 3075, ']': 2486, '`': 2088, '}': 1618, 'b': 1386, 'e': 1108, 'h': 951, 'k': 747, 'n': 612, 'q': 479, 't': 380, 'w': 305, 'z': 271, 'C': 217, 'F': 178, 'I': 132, 'L': 113, 'O': 101, 'R': 82, 'U': 64, 'X': 46, '0': 39, '3': 34, '6': 28, '9': 23, '&': 15, ')': 13, '#': 12, '<': 5, '/': 4, '_': 3, '\\': 2, '|': 1, '?': 2, 'a': 2, ',': 1, 'g': 1, 'v': 1, 'c': 1, 'd': 1, 'j': 1, 'm': 1, 'p': 1, 's': 1, 'y': 1, 'B': 1, 'E': 1, 'H': 1, 'K': 1, 'N': 1, 'Q': 1, 'T': 1, 'W': 1, 'Z': 1, '2': 1, '5': 1, '8': 1, '"': 1, '%': 1, '(': 1, '+': 1, '.': 1, ';': 1, '>': 1, '[': 1, '^': 1, '{': 1, '~': 1}
    #letters = list(weighted.keys())
    #weights = list(weighted.values())
    ########################################################

    # remove the trailing '_hash'
    solution_file = challenge_hash_file[:-5]
    with open(solution_file, 'w') as f:
        f.write(password)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', title='command')
    subparsers.required = True
    parser_g = subparsers.add_parser('g', help='passwordgen')
    parser_g.add_argument(
        'password_file',
        nargs='?',
        default='password',
        help='default: password'
    )
    parser_g.add_argument(
        'password_hash_file',
        nargs='?',
        default='password_hash',
        help='default: password_hash'
    )
    parser_v = subparsers.add_parser('v', help='verify password against hash')
    parser_v.add_argument(
        'password_hash_file',
        nargs='?',
        default='password_hash',
        help='default: password_hash'
    )
    parser_c = subparsers.add_parser('c', help='challenge')
    parser_c.add_argument(
        'file',
        nargs='?',
        default='challenge_hash',
        help='challenge password digest file; default: challenge_hash')
    args = parser.parse_args()

    if args.command == 'g':
        pw = generate_password()
        print(pw)
        with open(args.password_file, 'w') as f:
            f.write(pw)

        hasher = SHA512.new()
        hasher.update(pw.encode('utf-8'))

        with open(args.password_hash_file, 'w') as f:
            f.write(hasher.hexdigest())

        return
    
    if args.command == 'v':
        pw = getpass.getpass("enter password to verify against hash:")
        with open(args.password_hash_file, 'r') as f:
            pw_hash = f.read()
        if verify(pw, pw_hash):
            print("PW correct")
            return 0
        else:
            print("PW incorrect")
            return -1

    if args.command == 'c':
        if not args.file.endswith("_hash"):
            print("provide a challenge hash file")
            return -1
        solve_challenge(args.file)
        check_challenge(args.file[:-5])

if __name__ == "__main__":
    sys.exit(main())
