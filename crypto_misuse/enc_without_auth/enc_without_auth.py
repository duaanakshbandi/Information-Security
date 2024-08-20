#!/usr/bin/python3
import sys
import socket
import json
import base64
import os
import os.path
import argparse

from Cryptodome.Util.Padding import pad, unpad
from util import check_challenge
from utils import State, encrypt, decrypt

HOST='0.0.0.0'
highport = 6667
lowport = 6666

aes_block_length = 16
id_len = 8

def readTranscript(fname):
    with open(fname, "r") as f:
        ts = json.load(f)
    
    return [ [base64.b64decode(packet) for packet in record] for record in ts]

def openConnection(high):
    if high:
        port = highport
    else:
        port = lowport

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, port))
    return s

def leakID():
    with open("configs/highCard.json", 'r') as f:
        config = json.load(f)
    
    return base64.b64decode(config["id"])

def sendAndWaitReply(socket, packet):
    socket.sendall(packet)
    return socket.recv(1024)

def bitsToBytes(bit_array):
    assert len(bit_array) % 8 == 0, "only accept full bytes"
    for x in bit_array:
        assert x in (0, 1), "input not a bit array"
    res = []
    for i in range(0, len(bit_array), 8):
        byte = 0
        for j in range(8):
            byte |= bit_array[i+j] << (7-j)
        res.append(byte)

    return bytearray(res)

def bytesToBits(byte_array):
    res = []
    for x in byte_array:
        for j in range(8):
            bit = (x >> (7-j)) & 1
            res.append(bit)
    return res

def solve_challenge(fname):

    #read sniffed low-security transcript between card and scanner
    sniffed = readTranscript(fname)

    #open connections to both scanners
    shigh = openConnection(True)
    slow = openConnection(False)

    #read in the id of high-security card ("database leak")
    cardID = leakID()

########################################################################
# enter your code here
    # Get required sniffed information
    iv_p = sniffed[0][0][:aes_block_length]
    ct_e = sniffed[0][0][aes_block_length:2 * aes_block_length]

    # Communicate with low scanner - Encrypt HighCardID
    packet = iv_p + ct_e + pad(cardID, aes_block_length)
    info = sendAndWaitReply(slow, packet)

    # Get encrypted HighCardID and its IV
    iv_p_high = info[1 * aes_block_length:2 * aes_block_length]
    ct_e_high = info[2 * aes_block_length:3 * aes_block_length]

    # Communicate with high scanner - First part of the challenge
    packet = iv_p_high + ct_e_high + pad(cardID, aes_block_length)
    info = sendAndWaitReply(shigh, packet)

    # Get high scanner nonce
    h_nonce = info[4 * aes_block_length:5 * aes_block_length]

    # Get low scanner nonce and session ID
    l_nonce = sniffed[0][1][4 * aes_block_length:5 * aes_block_length]
    sess = sniffed[0][2][2 * aes_block_length:3 * aes_block_length]

    # Step 1: Ns_low XOR Sess = Goal (We acquire the Goal bits here)
    # Step 2: Ns_high XOR Sess = Goal (Transform this so that the end result is new Sess)
    # step 2: Ns_high XOR Goal = Sess
    # Ns_low XOR Sess
    bits1 = bytesToBits(l_nonce)
    bits2 = bytesToBits(sess)
    goal = []
    for bit1, bit2 in zip(bits1, bits2):
        goal.append(bit1 ^ bit2)

    # Ns_high XOR Goal
    bits1 = bytesToBits(h_nonce)
    bits2 = goal
    newSess = []
    for bit1, bit2 in zip(bits1, bits2):
        newSess.append(bit1 ^ bit2)
    newSessBytes = bitsToBytes(newSess)

    # Get required data for final packet
    iv_start = info[:1 * aes_block_length]
    id_c_s = info[1 * aes_block_length:2 * aes_block_length]
    l_nonce_e = sniffed[0][2][3 * aes_block_length:4 * aes_block_length]
    cmd = sniffed[0][2][4 * aes_block_length:5 * aes_block_length]

    # Open the holy doors to the almighty treasures
    packet = iv_start + id_c_s + newSessBytes + l_nonce_e + cmd
    sendAndWaitReply(shigh, packet)
########################################################################


def main():
    parser = argparse.ArgumentParser()  
    subparsers = parser.add_subparsers(dest='command', title='command')
    subparsers.required = True
    parser_c = subparsers.add_parser('c', help='challenge')
    parser_c.add_argument('sniffed_transcript', nargs='?', default='sniffed.json', help='default: sniffed.json')
    args = parser.parse_args()
    
    if args.command == 'c':

        if os.path.isfile('highdoor'):
            os.remove('highdoor')

        solve_challenge(args.sniffed_transcript)
        check_challenge('highcard')
        check_challenge('highdoor')
        return


if __name__ == "__main__":
    sys.exit(main())
