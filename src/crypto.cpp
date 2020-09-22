#include "headers.h"


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
