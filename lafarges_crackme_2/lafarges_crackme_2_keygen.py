#!/usr/bin/env python3
# coding=utf-8

"""
Keygen for Lafarges crackme_2 challenge
=======================================
http://crackmes.de/users/lafarge/lafarges_crackme_2/

Simple challenge that asks for a 'Username' and 'Reg. code'. The exe generates the valid
reg code from the username (which must be longer than 4). It does this in 6 steps:

*Note:* because of a bug(?) in the way the crackme checks for the string length
    (lstrlena @ 0040116A), all the steps actually skip the first letter of the username
    and overflow one past the len of the username. Keep that in mind when reading the
    steps

1. Iterate over each byte in the username from left to right. For each byte XOR it with
    `i % 5` (`i` being the current index) in the `STEP1_KEY` below. Then store the original
    byte from the username into `key[i]`.

2. Iterate over each byte in the username from right to left (`strlen - i`). For each byte
    XOR it with `i % 5` (`i` being the current counter, starting at 0) in the
    `STEP2_KEY` below. Then store the original byte from the username into `key[i]`.

3. Repeat step 1 above, using the `STEP3_KEY` below for the initial XOR key array

4. Repeat step 2 above, using the `STEP4_KEY` below for the initial XOR key array

5. Iterate over each byte in the array and add its value to `i % 4` in a `sum` array that
    starts as `[0, 0, 0, 0]`. These four bytes are then converted to a `DWORD` (little endian)

6. Take the `DWORD` generated in step 5, and divide it by `0x0A` until you hit zero. For each
    division, take the remainder, add `0x30` to it, and append it to a string

7. Reverse the bytes in the string generated in step 6


Reversing the challenge
=======================

The challenge is easily reversed using OllyDbg, and the trial version of IDA Pro. Start by
running the binary to find strings that can be used as lookups in the debugger (for instance
putting in a username without a wrong reg code will lead you to the end of the key validation
check). Once this is found, load it up in IDA Pro and work backwards from the the final
reg code check to determine how the crackme generates the code to check the entered value
against. From there, using the locations found in IDA for important secionts of code
(XOR loops, etc), you can debug the crackme in OllyDbg to watch the data generated to double
check what you learned in IDA. Finally, re-implement the same algorithm to generate valid
keys for the crackme.

"""

import unittest


STEP1_KEY = [0xAA, 0x89, 0xC4, 0xFE, 0x46]
STEP2_KEY = [0x78, 0xF0, 0xD0, 0x03, 0xE7]
STEP3_KEY = [0xF7, 0xFD, 0xF4, 0xE7, 0xB9]
STEP4_KEY = [0xB5, 0x1B, 0xC9, 0x50, 0x73]


def lafarges_crackme_2_keygen(username):
    if len(username) < 4:
        raise ValueError("Username must have at least 4 chars...")

    # toss away the first character because of a bug(?) in the way the crackme checks
    # for the string length (lstrlena @ 0040116A), but pad a \x00 since strlen is still
    # the same
    buf = bytearray(username[1:], 'mbcs') + b'\x00'

    def _xor_left_to_right(xor_key):
        for i, c in enumerate(buf):
            xor_key[i % len(xor_key)], buf[i] = c, c ^ xor_key[i % len(xor_key)]
        return buf

    def _xor_right_to_left(xor_key):
        for i, c in enumerate(reversed(buf)):
            xor_key[i % len(xor_key)], buf[(len(buf)-1)-i] = c, c ^ xor_key[i % len(xor_key)]
        return buf

    # [:] ensures we copy the array instead of point to it
    _xor_left_to_right(STEP1_KEY[:])  # step 1
    _xor_right_to_left(STEP2_KEY[:])  # step 2
    _xor_left_to_right(STEP3_KEY[:])  # step 3
    _xor_right_to_left(STEP4_KEY[:])  # step 4

    # step 5
    sums = [0] * 4
    for i, b in enumerate(buf):
        sums[i % 4] = (b + sums[i % 4]) & 0xFF
    num = int.from_bytes(sums, byteorder='little')

    # step 6
    answer = []
    while (num & num) != 0:
        rem, num = num % 0xA, num//0xA
        answer.append(rem + 0x30)
    return ''.join(chr(b) for b in reversed(answer))  # step 7, reverse the string


class TestKeygen(unittest.TestCase):
    """ Tests a few 'username' inputs agains known reg codes """

    def test_user1(self):
        self.assertEqual(lafarges_crackme_2_keygen('user1'), '3277538028', msg='Key for "user1"')

    def test_asdf(self):
        self.assertEqual(lafarges_crackme_2_keygen('asdf'), '3569158525', msg='Key for "asdf"')

    def test_unicode(self):
        self.assertEqual(lafarges_crackme_2_keygen('>¬.¬>'), '3431270807', msg='Key for ">¬.¬>"')


if __name__ == '__main__':
    unittest.main()
