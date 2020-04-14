#include "stdafx.h"

int __cdecl wmain(int argc, wchar_t* argv[]) {
	BYTE input[] = { 'A', 'B', 'C', 'D' };
	ULONG inputSize = sizeof(input);
	DWORD hashSize = 0;
	PBYTE hashValue = NULL;

	HashWorker worker(input, inputSize);
	worker.calHash();

	hashValue = worker.getHash();
	hashSize = worker.getHashSize();
	PrintBytes(hashValue, hashSize);

	return 0;
}