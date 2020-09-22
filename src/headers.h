#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winternl.h>
#include <iostream>

#include <tchar.h> 
#include <strsafe.h>

#pragma comment(lib, "User32.lib")


int AESDecrypt(char* payload, DWORD payload_len, char* key, size_t keylen);

void Inject64(unsigned char* shellcode, int shellcode_len);
