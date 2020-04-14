#pragma once
#include "stdafx.h"

void PrintBytes(IN BYTE* pbPrintData, IN DWORD cbDataLen);
LARGE_INTEGER getFileSize(HANDLE _hFile);
LARGE_INTEGER getFileSize(LPCWSTR _filePath);
