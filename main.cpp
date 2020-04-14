#include "stdafx.h"

int __cdecl wmain(int argc, wchar_t* argv[]) {
	HashWorker worker;
	DWORD hashSize = 0;
	PBYTE hashValue = NULL;

	BYTE input[] = { 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C' };
	ULONG inputSize = sizeof(input);
	if (!worker.calHash(input, inputSize)) {
		std::cerr << "@calHash failed!" << std::endl;
		return 1;
	}
	hashValue = worker.getHash();
	hashSize = worker.getHashSize();
	PrintBytes(hashValue, hashSize);

	HANDLE hFile = CreateFileW(L"C:\\@Data\\ubuntu.iso", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!worker.calHash(&hFile, 0, 1073741824)) {
		std::cerr << "@calHash failed!" << std::endl;
		return 1;
	}
	hashValue = worker.getHash();
	hashSize = worker.getHashSize();
	PrintBytes(hashValue, hashSize);

	return 0;
}