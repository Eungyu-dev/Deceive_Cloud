#pragma once
#include "stdafx.h"

class HashWorker {
private:
    BCRYPT_ALG_HANDLE       hAlg;
    BCRYPT_HASH_HANDLE      hHash;
    NTSTATUS                status;
    DWORD                   cbData,
                            cbHash,
                            cbHashObject;
    PBYTE                   pbHashObject,
                            pbHash;

public:
    HashWorker();
	~HashWorker();
    BOOL calHash(PBYTE _rgbMsg, ULONG _rgbMsgSize);
    BOOL calHash(PBYTE _rgbMsg, ULONG _rgbMsgSize, LPCWSTR _hashType);
    BOOL calHash(HANDLE* _hFile, ULONG _offset, ULONG _allocSize);
    BOOL calHash(HANDLE* _hFile, ULONG _offset, ULONG _allocSize, LPCWSTR _hashType);
	PBYTE getHash();
    DWORD getHashSize();
};