//    G2Dumper - offset dumper for Grounded2Minimal
//    Copyright (C) 2026  x0reaxeax
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <Windows.h>
#include <stdio.h>

DWORD GetTextRVA(
    LPCBYTE lpMemoryMappedFile
) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) lpMemoryMappedFile;
    if (IMAGE_DOS_SIGNATURE != pDosHeader->e_magic) {
        fprintf(
            stderr,
            "[-] Invalid DOS header signature: 0x%X\n",
            pDosHeader->e_magic
        );
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS) (lpMemoryMappedFile + pDosHeader->e_lfanew);
    if (IMAGE_NT_SIGNATURE != pNtHeaders->Signature) {
        fprintf(
            stderr,
            "[-] Invalid NT header signature: 0x%X\n",
            pNtHeaders->Signature
        );
        return 0;
    }

    PIMAGE_SECTION_HEADER pSectionHeaders = \
        (PIMAGE_SECTION_HEADER) (lpMemoryMappedFile + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (0 == strcmp(
            (LPCSTR) pSectionHeaders[i].Name, 
            ".text"
        )) {
            return pSectionHeaders[i].VirtualAddress - pSectionHeaders[i].PointerToRawData;
        }
    }
    return 0;
}

LPCBYTE SigScan(
    LPCBYTE lpBase,
    SIZE_T nSearchSize,
    LPCBYTE lpPattern,
    SIZE_T nPatternSize
) {
    // pattern looks like "8F ? 45 23 ?" or so..
    for (SIZE_T i = 0; i <= nSearchSize - nPatternSize; i++) {
        BOOL bFound = TRUE;
        for (SIZE_T j = 0; j < nPatternSize; j++) {
            if (lpPattern[j] != '?' && lpBase[i + j] != lpPattern[j]) {
                bFound = FALSE;
                break;
            }
        }
        if (bFound) {
            return lpBase + i;
        }
    }
    return NULL;
}

DWORD64 EvaluatePatternOffset(
    LPCSTR szTargetName,
    DWORD dwTextRVA,
    LPCBYTE lpPatternAddress,
    LPCBYTE lpMemoryMappedFile
) {
    printf(
        " ** Found %s pattern at offset: 0x%llX (0x%llX)\n",
        szTargetName,
        (DWORD64) (lpPatternAddress - lpMemoryMappedFile),
        (DWORD64) (lpPatternAddress - lpMemoryMappedFile) + dwTextRVA
    );

    DWORD dwRelativeOffset = *(LPDWORD) (lpMemoryMappedFile + (lpPatternAddress - lpMemoryMappedFile) + 3);
    printf(
        " ** %s relative offset: 0x%X\n",
        szTargetName,
        dwRelativeOffset
    );
    DWORD64 qwGlobalObjectAddress = (DWORD64) (lpPatternAddress - lpMemoryMappedFile) + 7 + dwRelativeOffset;
    printf(
        "[+] %s global variable address offset: 0x%llX\n",
        szTargetName,
        qwGlobalObjectAddress + dwTextRVA
    );

    return qwGlobalObjectAddress + dwTextRVA;
}

int main(int argc, const char *argv[]) {
    if (argc < 2) {
        printf("Usage: G2Dumper <path_to_grounded2exe>\n");
        return EXIT_FAILURE;
    }

    LPCBYTE lpMemoryMappedFile = NULL;
    FILE *fpExe = NULL;

    if (EXIT_SUCCESS != fopen_s(
        &fpExe,
        argv[1],
        "rb"
    )) {
        fprintf(
            stderr,
            "[-] Failed to open file: %s\n",
            argv[1]
        );
        return EXIT_FAILURE;
    }

    fseek(fpExe, 0, SEEK_END);
    SIZE_T nFileSize = ftell(fpExe);
    fseek(fpExe, 0, SEEK_SET);

    lpMemoryMappedFile = VirtualAlloc(
        NULL,
        nFileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (NULL == lpMemoryMappedFile) {
        fprintf(
            stderr,
            "[-] Failed to allocate memory for file mapping: E%lu\n",
            GetLastError()
        );
        fclose(fpExe);
        return EXIT_FAILURE;
    }

    SIZE_T nBytesRead = fread(
        (LPVOID) lpMemoryMappedFile,
        1,
        nFileSize,
        fpExe
    );

    if (nBytesRead != nFileSize) {
        fprintf(
            stderr,
            "[-] Failed to read entire file into memory: R%llu != F%llu\n",
            (DWORD64) nBytesRead,
            (DWORD64) nFileSize
        );
        goto _RYUJI;
    }

    //48 89 1D ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C4
    BYTE abGWorldPattern[] = { 0x48, 0x89, 0x1D, '?', '?', '?', '?', 0x48, 0x8D, 0x05, '?', '?', '?', '?', 0x48, 0x83, 0xC4 };
    // 48 8D 0D ? ? ? ? 4C 89 7D ? 4C 89 7D ? E8
    BYTE abGNamesPattern[] = { 0x48, 0x8D, 0x0D, '?', '?', '?', '?', 0x4C, 0x89, 0x7D, '?', 0x4C, 0x89, 0x7D, '?', 0xE8 };
    // 48 89 15 ? ? ? ? 85 C0 7E ? 4C 8B C3 44 8B CB
    BYTE abGObjectsPattern[] = { 0x48, 0x89, 0x15, '?', '?', '?', '?', 0x85, 0xC0, 0x7E, '?', 0x4C, 0x8B, 0xC3, 0x44, 0x8B, 0xCB };
    // 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 80 3D ? ? ? ? ? 48 8B F2 ? ? 48 8B F9 74 ? 4C 8D 05 ? ? ? ? EB
    BYTE abAppendStringPattern[] = { 0x48, 0x89, 0x5C, 0x24, '?', 0x48, 0x89, 0x74, 0x24, '?', 0x57, 0x48, 0x83, 0xEC, '?', 0x80, 0x3D, '?', '?', '?', '?', '?', 0x48, 0x8B, 0xF2, '?', '?', 0x48, 0x8B, 0xF9, 0x74, '?', 0x4C, 0x8D, 0x05, '?', '?', '?', '?', 0xEB };
    
    DWORD64 qwGWorldOffset, qwGNamesOffset, qwGObjectsOffset;
    LPCBYTE lpGWorldPatternAddy = SigScan(
        lpMemoryMappedFile,
        nFileSize,
        abGWorldPattern,
        sizeof(abGWorldPattern)
    );

    if (NULL == lpGWorldPatternAddy) {
        fprintf(
            stderr,
            "[-] Failed to find GWorld pattern in file.\n"
        );
        goto _RYUJI;
    }

    DWORD dwTextRVA = GetTextRVA(lpMemoryMappedFile);
    qwGWorldOffset = EvaluatePatternOffset(
        "GWorld",
        dwTextRVA,
        lpGWorldPatternAddy,
        lpMemoryMappedFile
    );

    LPCBYTE lpGNamesPatternAddy = SigScan(
        lpMemoryMappedFile,
        nFileSize,
        abGNamesPattern,
        sizeof(abGNamesPattern)
    );

    if (NULL == lpGNamesPatternAddy) {
        fprintf(
            stderr,
            "[-] Failed to find GNames pattern in file.\n"
        );
        goto _RYUJI;
    }

    qwGNamesOffset = EvaluatePatternOffset(
        "GNames",
        dwTextRVA,
        lpGNamesPatternAddy,
        lpMemoryMappedFile
    );

    LPCBYTE lpGObjectsPatternAddy = SigScan(
        lpMemoryMappedFile,
        nFileSize,
        abGObjectsPattern,
        sizeof(abGObjectsPattern)
    );

    if (NULL == lpGObjectsPatternAddy) {
        fprintf(
            stderr,
            "[-] Failed to find GObjects pattern in file.\n"
        );
        goto _RYUJI;
    }

    qwGObjectsOffset = EvaluatePatternOffset(
        "GObjects",
        dwTextRVA,
        lpGObjectsPatternAddy,
        lpMemoryMappedFile
    );

    LPCBYTE lpAppendStringPatternAddy = SigScan(
        lpMemoryMappedFile,
        nFileSize,
        abAppendStringPattern,
        sizeof(abAppendStringPattern)
    );

    if (NULL == lpAppendStringPatternAddy) {
        fprintf(
            stderr,
            "[-] Failed to find AppendString pattern in file.\n"
        );
        goto _RYUJI;
    }

    printf("[+] AppendString function offset: 0x%llX\n",
        (DWORD64) (lpAppendStringPatternAddy - lpMemoryMappedFile) + dwTextRVA
    );

    printf(
        "\n"
        " :: GWorld   : 0x%llX\n"
        " :: GNames   : 0x%llX\n"
        " :: GObjects : 0x%llX\n\n",
        qwGWorldOffset,
        qwGNamesOffset,
        qwGObjectsOffset
    );
    system("pause");

_RYUJI:
    VirtualFree(
        (LPVOID) lpMemoryMappedFile,
        0,
        MEM_RELEASE
    );

    fclose(fpExe);
    return EXIT_SUCCESS;
}
