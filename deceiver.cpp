#include "stdafx.h"

HashWorker::HashWorker() {
    std::cout << "@HashWorker called!" << std::endl;
    this->hAlg = NULL;
    this->hHash = NULL;
    this->status = STATUS_UNSUCCESSFUL;
    this->cbData = 0;
    this->cbHash = 0;
    this->cbHashObject = 0;
    this->pbHashObject = NULL;
    this->pbHash = NULL;
}

HashWorker::~HashWorker() {
    std::cout << "@~HashWorker called!" << std::endl;
    if (hAlg)           BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash)          BCryptDestroyHash(hHash);
    if (pbHashObject)   HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)         HeapFree(GetProcessHeap(), 0, pbHash);
}

/****************************** _hashType ******************************
[Default: BCRYPT_MD5_ALGORITHM]
BCRYPT_MD2_ALGORITHM    BCRYPT_MD4_ALGORITHM    BCRYPT_SHA512_ALGORITHM
BCRYPT_SHA1_ALGORITHM   BCRYPT_SHA256_ALGORITHM BCRYPT_SHA384_ALGORITHM 
***********************************************************************/

BOOL HashWorker::calHash(PBYTE _rgbMsg, ULONG _rgbMsgSize) {
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(hHash, _rgbMsg, _rgbMsgSize, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    std::cout << "@HashWorker::calHash Successful!" << std::endl;
    return true;

Cleanup:
    std::cerr << "@HashWorker::Cleanup called!" << std::endl;
    if (hAlg)           BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash)          BCryptDestroyHash(hHash);
    if (pbHashObject)   HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)         HeapFree(GetProcessHeap(), 0, pbHash);
    return false;
}

BOOL HashWorker::calHash(PBYTE _rgbMsg, ULONG _rgbMsgSize, LPCWSTR _hashType) {
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, _hashType, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(hHash, _rgbMsg, _rgbMsgSize, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    std::cout << "@HashWorker::calHash Successful!" << std::endl;
    return true;

Cleanup:
    std::cerr << "@HashWorker::Cleanup called!" << std::endl;
    if (hAlg)           BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash)          BCryptDestroyHash(hHash);
    if (pbHashObject)   HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)         HeapFree(GetProcessHeap(), 0, pbHash);
    return false;
}

BOOL HashWorker::calHash(HANDLE* _hFile, ULONG _offset, ULONG _allocSize) {
    DWORD dwPos = 0, dwBytesRead = 0;
    PBYTE fileBuff = NULL;
    LARGE_INTEGER offset = { 0 };

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    fileBuff = (PBYTE)malloc(_allocSize);
    offset.QuadPart = _offset;
    if (offset.QuadPart > getFileSize(_hFile).QuadPart) {
        wprintf(L"**** offset has wrong value\n");
        goto Cleanup;
    }

    dwPos = SetFilePointerEx(*_hFile, offset, NULL, FILE_BEGIN);
    while (ReadFile(*_hFile, fileBuff, _allocSize, &dwBytesRead, NULL) && dwBytesRead > 0) {
        if (!NT_SUCCESS(status = BCryptHashData(hHash, fileBuff, dwBytesRead, 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
            goto Cleanup;
        }
    }
    free(fileBuff);
    fileBuff = NULL;
    CloseHandle(*_hFile);

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }


    std::cout << "@HashWorker::calHash Successful!" << std::endl;
    return true;

Cleanup:
    std::cerr << "@HashWorker::Cleanup called!" << std::endl;
    if (hAlg)           BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash)          BCryptDestroyHash(hHash);
    if (pbHashObject)   HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)         HeapFree(GetProcessHeap(), 0, pbHash);
    if (fileBuff)       free(fileBuff); fileBuff = NULL;
    return false;
}

BOOL HashWorker::calHash(HANDLE* _hFile, ULONG _offset, ULONG _allocSize, LPCWSTR _hashType) {
    DWORD dwPos = 0, dwBytesRead = 0;
    PBYTE fileBuff = NULL;
    LARGE_INTEGER offset = { 0 };

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, _hashType, NULL, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash object on the heap
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash) {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }


    //hash some data
    fileBuff = (PBYTE)malloc(_allocSize);
    offset.QuadPart = _offset;
    if (offset.QuadPart > getFileSize(_hFile).QuadPart) {
        wprintf(L"**** offset has wrong value\n");
        goto Cleanup;
    }

    dwPos = SetFilePointerEx(*_hFile, offset, NULL, FILE_BEGIN);
    while (ReadFile(*_hFile, fileBuff, _allocSize, &dwBytesRead, NULL) && dwBytesRead > 0) {
        if (!NT_SUCCESS(status = BCryptHashData(hHash, fileBuff, dwBytesRead, 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
            goto Cleanup;
        }
    }
    free(fileBuff);
    fileBuff = NULL;
    CloseHandle(*_hFile);

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    std::cout << "@HashWorker::calHash Successful!" << std::endl;
    return true;

Cleanup:
    std::cerr << "@HashWorker::Cleanup called!" << std::endl;
    if (hAlg)           BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hHash)          BCryptDestroyHash(hHash);
    if (pbHashObject)   HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash)         HeapFree(GetProcessHeap(), 0, pbHash);
    if (fileBuff)       free(fileBuff); fileBuff = NULL;
    return false;
}

PBYTE HashWorker::getHash() {
    return this->pbHash;
}

DWORD HashWorker::getHashSize() {
    return this->cbHash;
}