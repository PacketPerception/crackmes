Keygen for Lafarges crackme_2 challenge
=======================================

| | |
| ---- | ---- | 
| **From:** | http://crackmes.de/users/lafarge/lafarges_crackme_2/ |
| **Solution:** | [lafarges_crackme_2_keygen.py](lafarges_crackme_2_keygen.py) |
| **Challenge:** | [lafarge-crackme2.zip](lafarge-crackme2.zip) |


The Challenge
-------------

Simple keygen that asks for a 'Username' and 'Reg. code'. The exe generates the valid
reg code from the username (which must be longer than 4). It does this in 7 steps:


**Note:** because of a bug(?) in the way the crackme checks for the string length
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

The challenge is easily reversed using [OllyDbg][olly], and the trial version of [IDA Pro][ida].
Start by running the binary to find strings that can be used as lookups in the debugger (for
instance putting in a username without a wrong reg code will lead you to the end of the key
validation check). Once this is found, load it up in [IDA Pro][ida] and work backwards from the the
final reg code check to determine how the crackme generates the code to check the entered value
against. From there, using the locations found in [IDA Pro][ida] for important secionts of code (XOR
loops, etc), you can debug the crackme in [OllyDbg][olly] to watch the data generated to double
check what you learned in [IDA Pro][ida]. Finally, re-implement the same algorithm to generate valid
keys for the crackme.

[olly]: http://www.ollydbg.de/
[ida]: https://www.hex-rays.com/products/ida/index.shtml
