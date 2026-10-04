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

typedef DWORD64 QWORD, QWORD64, *PQWORD, *PQWORD64;

typedef struct _DUMPER_OPTIONS {
    LPCSTR InputPath;
    LPCSTR JsonOutputPath;
    BOOL PauseOnExit;
} DUMPER_OPTIONS, *PDUMPER_OPTIONS;

typedef struct _DUMPED_OFFSETS {
    QWORD GObjects;
    QWORD AppendString;
    QWORD GNames;
    QWORD GWorld;
    QWORD ProcessEvent;
} DUMPED_OFFSETS, *PDUMPED_OFFSETS;

VOID PrintUsage(
    LPCSTR cszExecutableName
) {
    printf(
        "Usage:\n"
        "  %s <path_to_grounded2exe>\n"
        "  %s <path_to_grounded2exe> --json <output_file>\n"
        "  %s <path_to_grounded2exe> --no-pause\n"
        "\n"
        "Options:\n"
        "  --json <path>   Write discovered offsets to a JSON file.\n"
        "                  This also disables the final pause.\n"
        "  --no-pause     Do not pause before exiting.\n",
        cszExecutableName,
        cszExecutableName,
        cszExecutableName
    );
}

BOOL ParseArguments(
    INT argc,
    LPCSTR CONST argv[],
    PDUMPER_OPTIONS lpOptions
) {
    if (NULL == lpOptions || argc < 2) {
        return FALSE;
    }

    lpOptions->InputPath = argv[1];
    lpOptions->JsonOutputPath = NULL;
    lpOptions->PauseOnExit = TRUE;

    for (INT i = 2; i < argc; ++i) {
        if (0 == strcmp(argv[i], "--json")) {
            if ((i + 1) >= argc) {
                fprintf(
                    stderr,
                    "[-] Missing output path after --json.\n"
                );
                return FALSE;
            }

            lpOptions->JsonOutputPath = argv[++i];

            // JSON mode is intended for CI/non-interactive use.
            lpOptions->PauseOnExit = FALSE;
        } else if (0 == strcmp(argv[i], "--no-pause")) {
            lpOptions->PauseOnExit = FALSE;
        } else {
            fprintf(
                stderr,
                "[-] Unknown argument: %s\n",
                argv[i]
            );
            return FALSE;
        }
    }

    return TRUE;
}

BOOL WriteOffsetsJson(
    LPCSTR szOutputPath,
    CONST DUMPED_OFFSETS* lpOffsets
) {
    if (NULL == szOutputPath || NULL == lpOffsets) {
        return FALSE;
    }

    FILE* fpOutput = NULL;

    errno_t iOpenResult = fopen_s(
        &fpOutput,
        szOutputPath,
        "wb"
    );

    if (0 != iOpenResult || NULL == fpOutput) {
        fprintf(
            stderr,
            "[-] Failed to open JSON output file: %s\n",
            szOutputPath
        );
        return FALSE;
    }

    INT iWriteResult = fprintf(
        fpOutput,
        "{\n"
        "  \"GObjects\": \"0x%08llX\",\n"
        "  \"AppendString\": \"0x%08llX\",\n"
        "  \"GNames\": \"0x%08llX\",\n"
        "  \"GWorld\": \"0x%08llX\",\n"
        "  \"ProcessEvent\": \"0x%08llX\"\n"
        "}\n",
        lpOffsets->GObjects,
        lpOffsets->AppendString,
        lpOffsets->GNames,
        lpOffsets->GWorld,
        lpOffsets->ProcessEvent
    );

    if (iWriteResult < 0) {
        fprintf(
            stderr,
            "[-] Failed to write JSON output file: %s\n",
            szOutputPath
        );

        fclose(fpOutput);
        return FALSE;
    }

    if (0 != fclose(fpOutput)) {
        fprintf(
            stderr,
            "[-] Failed to finalize JSON output file: %s\n",
            szOutputPath
        );
        return FALSE;
    }

    printf(
        "[+] Wrote offsets to: %s\n",
        szOutputPath
    );

    return TRUE;
}


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

// dwDisplacementOffset is the offset (from the start of the pattern) of the 4-byte
// relative displacement operand. The instruction is assumed to end 4 bytes after that
// (i.e. dwDisplacementOffset + sizeof(DWORD)), which is where RIP-relative addressing
// is computed from.
DWORD64 EvaluatePatternOffset(
    LPCSTR szTargetName,
    DWORD dwTextRVA,
    LPCBYTE lpPatternAddress,
    LPCBYTE lpMemoryMappedFile,
    DWORD dwDisplacementOffset
) {
    printf(
        " ** Found %s pattern at offset: 0x%llX (0x%llX)\n",
        szTargetName,
        (DWORD64) (lpPatternAddress - lpMemoryMappedFile),
        (DWORD64) (lpPatternAddress - lpMemoryMappedFile) + dwTextRVA
    );

    LONG lRelativeOffset = *(PLONG) (lpMemoryMappedFile + (lpPatternAddress - lpMemoryMappedFile) + dwDisplacementOffset);
    printf(
        " ** %s relative offset: 0x%X\n",
        szTargetName,
        lRelativeOffset
    );
    DWORD64 qwGlobalObjectAddress = (DWORD64) ((LONG64) (lpPatternAddress - lpMemoryMappedFile) + dwDisplacementOffset + sizeof(DWORD) + lRelativeOffset);
    printf(
        "[+] %s global variable address offset: 0x%llX\n",
        szTargetName,
        qwGlobalObjectAddress + dwTextRVA
    );

    return qwGlobalObjectAddress + dwTextRVA;
}

int main(int argc, const char *argv[]) {
    if (
        argc < 2 || 
        0 == strcmp(argv[1], "--help") || 
        0 == strcmp(argv[1], "-h")
    ) {
        PrintUsage(argv[0]);

        return argc < 2
            ? EXIT_FAILURE
            : EXIT_SUCCESS;
    }

    DUMPER_OPTIONS Options = { 0 };

    if (!ParseArguments(argc, argv, &Options)) {
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
    }

    INT iExitCode = EXIT_FAILURE;

    LPCBYTE lpMemoryMappedFile = NULL;
    FILE *fpExe = NULL;

    DUMPED_OFFSETS Offsets = { 0 };

    if (
        EXIT_SUCCESS != fopen_s(
            &fpExe,
            Options.InputPath,
            "rb"
        )
        ) {
        fprintf(
            stderr,
            "[-] Failed to open file: %s\n",
            Options.InputPath
        );
        return EXIT_FAILURE;
    }

    if (0 != fseek(
        fpExe,
        0,
        SEEK_END
    )) {
        fprintf(
            stderr,
            "[-] Failed to seek to end of input file.\n"
        );
        goto _RYUJI;
    }

    LONG lFileSize = ftell(fpExe);

    if (lFileSize <= 0) {
        fprintf(
            stderr,
            "[-] Failed to determine input file size.\n"
        );
        goto _RYUJI;
    }

    SIZE_T nFileSize = (SIZE_T) lFileSize;

    if (0 != fseek(fpExe, 0, SEEK_SET)) {
        fprintf(
            stderr,
            "[-] Failed to seek to start of input file.\n"
        );
        goto _RYUJI;
    }

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
        goto _RYUJI;
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

    DWORD dwTextRVA =
        GetTextRVA(lpMemoryMappedFile);

    if (0 == dwTextRVA) {
        goto _RYUJI;
    }

    //
    // GWorld
    //
    // 48 89 1D ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C4
    //
    BYTE abGWorldPattern[] = {
        0x48, 0x89, 0x1D,
        '?', '?', '?', '?',
        0x48, 0x8D, 0x05,
        '?', '?', '?', '?',
        0x48, 0x83, 0xC4
    };

    //
    // GNames
    //
    // 48 8D 0D ? ? ? ? 4C 89 7D ? 4C 89 7D ? E8
    //
    BYTE abGNamesPattern[] = {
        0x48, 0x8D, 0x0D,
        '?', '?', '?', '?',
        0x4C, 0x89, 0x7D, '?',
        0x4C, 0x89, 0x7D, '?',
        0xE8
    };

    //
    // GObjects
    //
    // 48 89 15 ? ? ? ? 85 C0 7E ? 4C 8B C3 44 8B CB
    //
    BYTE abGObjectsPattern[] = {
        0x48, 0x89, 0x15,
        '?', '?', '?', '?',
        0x85, 0xC0, 0x7E, '?',
        0x4C, 0x8B, 0xC3,
        0x44, 0x8B, 0xCB
    };

    //
    // AppendString
    //
    // 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ?
    // 80 3D ? ? ? ? ? 48 8B F2 ? ? 48 8B F9 74 ?
    // 4C 8D 05 ? ? ? ? EB
    //
    BYTE abAppendStringPattern[] = {
        0x48, 0x89, 0x5C, 0x24, '?',
        0x48, 0x89, 0x74, 0x24, '?',
        0x57,
        0x48, 0x83, 0xEC, '?',
        0x80, 0x3D,
        '?', '?', '?', '?',
        '?',
        0x48, 0x8B, 0xF2,
        '?', '?',
        0x48, 0x8B, 0xF9,
        0x74, '?',
        0x4C, 0x8D, 0x05,
        '?', '?', '?', '?',
        0xEB
    };

    //
    // ProcessEvent xref
    //
    BYTE abProcessEventXRefPattern[] = {
        0x75, '?',
        0x4C, 0x8B, 0xC5,
        0x48, 0x8B, 0xD3,
        0x48, 0x8B, 0xCF,
        0xE8
    };

    LPCBYTE lpGWorldPatternAddy =
        SigScan(
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

    Offsets.GWorld =
        EvaluatePatternOffset(
            "GWorld",
            dwTextRVA,
            lpGWorldPatternAddy,
            lpMemoryMappedFile,
            3
        );

    LPCBYTE lpGNamesPatternAddy =
        SigScan(
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

    Offsets.GNames =
        EvaluatePatternOffset(
            "GNames",
            dwTextRVA,
            lpGNamesPatternAddy,
            lpMemoryMappedFile,
            3
        );

    LPCBYTE lpGObjectsPatternAddy =
        SigScan(
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

    Offsets.GObjects =
        EvaluatePatternOffset(
            "GObjects",
            dwTextRVA,
            lpGObjectsPatternAddy,
            lpMemoryMappedFile,
            3
        );

    LPCBYTE lpAppendStringPatternAddy =
        SigScan(
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

    Offsets.AppendString =
        (DWORD64) (
            lpAppendStringPatternAddy -
            lpMemoryMappedFile
            ) +
        dwTextRVA;

    printf(
        "[+] AppendString function offset: 0x%llX\n",
        Offsets.AppendString
    );

    LPCBYTE lpProcessEventXRefPatternAddy =
        SigScan(
            lpMemoryMappedFile,
            nFileSize,
            abProcessEventXRefPattern,
            sizeof(abProcessEventXRefPattern)
        );

    if (NULL == lpProcessEventXRefPatternAddy) {
        fprintf(
            stderr,
            "[-] Failed to find ProcessEvent xref pattern in file.\n"
        );
        goto _RYUJI;
    }

    // Relative call offset is taken from the CALL instruction (last E8 byte), 
    // The displacement operand starts right after the pattern ends
    // (at sizeof(abProcessEventXRefPattern)), so EvaluatePatternOffset can compute the absolute
    // address of the ProcessEvent function the same way it does for GWorld/GNames/GObjects.
    /*
        .text:000000014386DFD2 75 0E                                                        jnz     short loc_14386DFE2
        .text:000000014386DFD4 4C 8B C5                                                     mov     r8, rbp
        .text:000000014386DFD7 48 8B D3                                                     mov     rdx, rbx
        .text:000000014386DFDA 48 8B CF                                                     mov     rcx, rdi
        .text:000000014386DFDD E8 BE 73 D3 FD                                               call    sub_1415A53A0
    */
    Offsets.ProcessEvent =
        EvaluatePatternOffset(
            "ProcessEvent",
            dwTextRVA,
            lpProcessEventXRefPatternAddy,
            lpMemoryMappedFile,
            (DWORD) sizeof(abProcessEventXRefPattern)
        );

    printf(
        "\n"
        " :: GObjects       : 0x%08llX\n"
        " :: AppendString   : 0x%08llX\n"
        " :: GNames         : 0x%08llX\n"
        " :: GWorld         : 0x%08llX\n"
        " :: ProcessEvent   : 0x%08llX\n"
        "\n",
        Offsets.GObjects,
        Offsets.AppendString,
        Offsets.GNames,
        Offsets.GWorld,
        Offsets.ProcessEvent
    );

    if (
        NULL != Options.JsonOutputPath &&
        !WriteOffsetsJson(
            Options.JsonOutputPath,
            &Offsets
        )
        ) {
        goto _RYUJI;
    }

    iExitCode = EXIT_SUCCESS;

    if (Options.PauseOnExit) {
        system("pause");
    }

_RYUJI:
    if (NULL != lpMemoryMappedFile) {
        VirtualFree(
            (LPVOID) lpMemoryMappedFile,
            0,
            MEM_RELEASE
        );
    }

    if (NULL != fpExe) {
        fclose(fpExe);
    }

    return iExitCode;
}