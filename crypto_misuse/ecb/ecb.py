#!/usr/bin/env python3

import os
import os.path
import sys
import argparse

from util import check_challenge

from Cryptodome.Cipher import AES
from scipy.io import wavfile
from Cryptodome.Hash import SHA256
import numpy as np
import struct


def enc_audio(fname, key):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    samplerate, pt = wavfile.read(fname)

    ct = []

    for sample in pt:
        ct_byte = cipher.encrypt(sample.tobytes() + bytes(15))
        ct.extend(struct.unpack("16B", ct_byte))

    wavfile.write(fname[:-4] + '_enc.wav', samplerate, np.array(list(ct)).astype(np.uint8))


def dec_audio(fname, key):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    samplerate, ct = wavfile.read(fname)
    pt = []
    ct_bytes = bytearray(ct)

    for index in range(0, len(ct_bytes), 16):
        pt_bytes = cipher.decrypt(ct_bytes[index : index + 16])
        pt.append(pt_bytes[0])

    wavfile.write(fname[:-8] + "_dec.wav", samplerate, np.array(list(pt)).astype(np.uint8))

class Response:
  offset = None
  map = {}
def find_offset_and_map(enc, plain_audio_piece):
    response = Response()
    offset = None
    map = {}
    size_of_encryption_block = 16
    length_of_encrypted_file = len(enc)
    number_of_blocks_in_encrypted_file = (int) (length_of_encrypted_file / size_of_encryption_block)
    length_of_plain_audio_piece = len(plain_audio_piece)

    for itteration in range(number_of_blocks_in_encrypted_file):
        map = {}
        for index in range(length_of_plain_audio_piece):
            start_index_of_current_block_in_encrypted_file = itteration * size_of_encryption_block + index * size_of_encryption_block
            ending_index_of_current_block_in_encrypted_file = start_index_of_current_block_in_encrypted_file + size_of_encryption_block

            current_block_in_encrypted_file = enc[start_index_of_current_block_in_encrypted_file : ending_index_of_current_block_in_encrypted_file]
            hashable_current_block_in_encrypted_file = tuple(current_block_in_encrypted_file)
            current_block_in_plain_audio_piece = plain_audio_piece[index]

            if hashable_current_block_in_encrypted_file in map:
                if map.get(hashable_current_block_in_encrypted_file) != current_block_in_plain_audio_piece:
                    #print("(!!!) same cipher block mapping to different plaintext")
                    break
            else:
                map[hashable_current_block_in_encrypted_file] = plain_audio_piece[index]
        if index == length_of_plain_audio_piece - 1:
            break
    if offset != None:
        print("couldn't find offset")
        return

    response.offset = itteration
    response.map = map
    return response

def decrypt_using_map(enc, map):
    size_of_encryption_block = 16
    length_of_encrypted_file = len(enc)
    number_of_blocks_in_encrypted_file = (int) (length_of_encrypted_file / size_of_encryption_block)
    plain_audio = []

    for itteration in range(number_of_blocks_in_encrypted_file):
        start_index_of_current_block_in_encrypted_file = itteration * size_of_encryption_block
        ending_index_of_current_block_in_encrypted_file = start_index_of_current_block_in_encrypted_file + size_of_encryption_block

        current_block_in_encrypted_file = enc[start_index_of_current_block_in_encrypted_file : ending_index_of_current_block_in_encrypted_file]
        hashable_current_block_in_encrypted_file = tuple(current_block_in_encrypted_file)

        if hashable_current_block_in_encrypted_file in map:
            plain_audio.append(map[hashable_current_block_in_encrypted_file])
        else:
            print("couldn't map cipherblock " , hashable_current_block_in_encrypted_file , " to any plaintext." )

    return  plain_audio


def solve_challenge(plain_audio_piece, enc_file):

    samplerate, enc = wavfile.read(enc_file)
    samplerate, plain_audio_piece = wavfile.read(plain_audio_piece)

    plain_audio = []
    
########################################################################
# enter your code here

    offset_and_map = find_offset_and_map(enc , plain_audio_piece)

    if offset_and_map.offset != None:
        plain_audio = decrypt_using_map(enc, offset_and_map.map)


########################################################################
    
    wavfile.write("audio.wav", samplerate, np.array(plain_audio))

    hasher = SHA256.new()
    hasher.update(bytearray(plain_audio))

    with open("audio_hash", 'w') as f:
        f.write(hasher.hexdigest() + '\n')


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', title='command')
    subparsers.required = True
    parser_e = subparsers.add_parser('e', help='encrypt')
    parser_e.add_argument('file', nargs='+')
    parser_d = subparsers.add_parser('d', help='decrypt')
    parser_d.add_argument('file', nargs='+')
    parser_h = subparsers.add_parser('h', help='hash')
    parser_h.add_argument('file', nargs='+')
    parser_g = subparsers.add_parser('g', help='keygen')
    parser_c = subparsers.add_parser('c', help='challenge')
    parser_c.add_argument(
        'audio_piece',
        nargs='?',
        default='audio_piece.wav',
        help='default: audio_piece.wav')
    parser_c.add_argument(
        'sniffed_stream',
        nargs='?',
        default='sniffed_stream.wav',
        help='default: sniffed_stream.wav')
    args = parser.parse_args()

    if args.command == 'g':
        key = os.urandom(16)
        with open('key', 'wb') as f:
            f.write(key)
        return

    if args.command == 'e' or args.command == 'd':
        if not os.path.isfile('key'):
            print('no key found, run key generation first')
            return -1
        else:
            with open('key', 'rb') as f:
                key = f.read()
            files = [
                t for t in args.file if (
                    os.path.isfile(t) and not t == 'key')]

    if args.command == 'h':
        for f in args.file:
            if not os.path.splitext(f)[1] == '.wav':
                print('only .wav files allowed')
                return -1
            else:
                samplerate, audio = wavfile.read(f)
                hasher = SHA256.new()
                hasher.update(audio.tobytes())

                with open(f[:-4] + "_hash", 'w') as f:
                    f.write(hasher.hexdigest() + '\n')
                return

    if args.command == 'e':
        # we don't encrypt already encrypted files
        files = [t for t in files if not t.endswith('_enc.wav')]
        if len(files) == 0:
            print('No valid files selected')
            return

        for f in files:
            enc_audio(f, key)

        return

    if args.command == 'd':
        # we only want encrypted files
        files = [t for t in files if t.endswith('_enc.wav')]
        if len(files) == 0:
            print('No valid files selected')
            return

        for f in files:
            dec_audio(f, key)

        return

    if args.command == 'c':
        solve_challenge(args.audio_piece, args.sniffed_stream)

        check_challenge('audio_hash')

        return


if __name__ == "__main__":
    sys.exit(main())
