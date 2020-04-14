#include "stdafx.h"

void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen) {
	DWORD dwCount = 0;
	for (dwCount = 0; dwCount < cbDataLen; dwCount++) {
		printf("%02x ", pbPrintData[dwCount]);
	}
	printf("\n");
	return;
}

LARGE_INTEGER getFileSize(HANDLE* _hFile) {
	if (*_hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "ERRORCODE: " << GetLastError() << std::endl;
		exit(-1);
	}

	LARGE_INTEGER larTmp = { 0 };
	GetFileSizeEx(*_hFile, &larTmp);
	return larTmp;
}

LARGE_INTEGER getFileSize(LPCWSTR _filePath) {
	HANDLE hFile = CreateFileW(_filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "ERRORCODE: " << GetLastError() << std::endl;
		exit(-1);
	}

	LARGE_INTEGER larTmp = { 0 };
	GetFileSizeEx(hFile, &larTmp);
	CloseHandle(hFile);
	return larTmp;
}