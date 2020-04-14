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
    PBYTE                   rgbMsg;
    ULONG                   rgbMsgSize;

public:
    HashWorker(PBYTE _rgbMsg, ULONG _rgbMsgSize);
	~HashWorker();
    BOOL calHash();
    BOOL calHash(LPCWSTR _hashType, ULONG _buffSize);
	PBYTE getHash();
    DWORD getHashSize();
};