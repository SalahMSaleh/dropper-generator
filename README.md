# malware-generator

Simple project to generate 32bit or 64bit undetectable droppers from shellcodes

Thanks to [@slaeryan](https://twitter.com/slaeryan) for the great help and advices.


# Installation

```
pip3 install -r requirments.txt
```

# Usage

```
$ ./generator.py -h
usage: generator.py [-h] [-a ARCH] binaryPath

Simple raw shellcode Dropper Generator

positional arguments:
  binaryPath            File containing raw shellcode

optional arguments:
  -h, --help            show this help message and exit
  -a ARCH, --arch ARCH  Shellcode Architecture (1=x64, 2=x86) (default=x64)
  -d, --debug           Generate cpp code with the executable for debuging
```

Create raw 64bit or 32bit shellcode with any tool you like here i will use msfvenom calc 64bit shellcode.
```
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
```

Then use my tool to generate a dropper for it.
```
$ ./generator.py calc.bin 
[*] Generating x64 Dropper for calc.bin
[+] Executable saved to output/calc.exe
```


## Todo
* add check for tools and dependencies.
* add option to generate direct from msfvenom.
* add option to pass .NET assemblies and use donut.
* add option to specifed output directory and output name.
