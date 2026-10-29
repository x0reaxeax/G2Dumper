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

#include "H2SS/SigScan64.h"

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
    QWORD FindFunctionChecked;
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
        "  \"ProcessEvent\": \"0x%08llX\",\n"
        "  \"FindFunctionChecked\": \"0x%08llX\"\n"
        "}\n",
        lpOffsets->GObjects,
        lpOffsets->AppendString,
        lpOffsets->GNames,
        lpOffsets->GWorld,
        lpOffsets->ProcessEvent,
        lpOffsets->FindFunctionChecked
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

        return argc < 2 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    DUMPER_OPTIONS Options = { 0 };

    if (!ParseArguments(argc, argv, &Options)) {
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
    }

    // shut the fopen warning up
    if (NULL == Options.InputPath) {
        fprintf(
            stderr,
            "[-] Input path is required.\n"
        );
        PrintUsage(argv[0]);
        return EXIT_FAILURE;
    }

    INT iExitCode = EXIT_FAILURE;

    LPCBYTE lpMemoryMappedFile = NULL;
    FILE *fpExe = NULL;

    DUMPED_OFFSETS Offsets = { 0 };

    if (EXIT_SUCCESS != fopen_s(&fpExe, Options.InputPath, "rb")) {
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

    UMASK mGWorldPattern[] = {
        0x48, 0x8B, '??', '??',
        0x48, 0x89, '??', '??', '??', '??', '0?',
        0x4C, 0x8B, '7?', '7?'
    };

    // unused cuz AppendString loads gnames at +0x20 (https://github.com/x0reaxeax/Grounded2Minimal/issues/49#issuecomment-6499518533)
    // this pattern is therefore within AppendString
    UMASK mGNamesPattern[] = {
        0x48, 0x8B, 0xF2, 0x8B, 0x19, 0x48, 0x8B, 0xF9,
        0x74, '??', 0x4C, 0x8D, 0x05, '??', '??', '??',
        '??', 0xEB, '??', 0x48, 0x8D, 0x0D, '??', '??',
        '??', '??', 0xE8, '??', '??', '??', '??', 0x4C,
        0x8B, 0xC0
    };

    UMASK mGObjectsPattern[] = {
        0x44, 0x8B, 0xC7, 0x48, 0x8D, 0x0D, '??', '??',
        '??', '??', 0x8B, 0xD6, 0xE8, '??', '??', '??',
        '??', 0xE9
    };

    //
    // AppendString
    //
    // 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ?
    // 80 3D ? ? ? ? ? 48 8B F2 ? ? 48 8B F9 74 ?
    // 4C 8D 05 ? ? ? ? EB
    //
    UMASK mAppendStringPattern[] = {
        0x48, 0x89, 0x5C, 0x24, '??',
        0x48, 0x89, 0x74, 0x24, '??',
        0x57,
        0x48, 0x83, 0xEC, '??',
        0x80, 0x3D, '??', '??', '??', '??', '??',
        0x48, 0x8B, 0xF2,
        '??', '??',
        0x48, 0x8B, 0xF9,
        0x74, '??',
        0x4C, 0x8D, 0x05, '??', '??', '??', '??',       // lea     r8, stru_???????? <GNames>
        0xEB
    };

    UMASK mProcessEventPattern[] = {
        0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55,
        0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, '??',
        '??', '??', '??', 0x48, 0x8D, 0x6C, 0x24, '??',
        0x48, 0x89, 0x9D, '??', '??', '??', '??', 0x48,
        0x8B, 0x05, '??', '??', '??', '??', 0x48, 0x33,
        0xC5, 0x48, 0x89, 0x85, '??', '??', '??', '??',
        0x8B, 0x41, 0x08
    };

    UMASK mFindFunctionCheckedPattern[] = {
        0x48, 0x89, 0x5C, 0x24, '??', 0x48, 0x89, 0x54,
        0x24, '??', 0x57, 0x48, 0x83, 0xEC, '??', 0x48,
        0x8B, 0xF9, 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x49, 0x10, 0xE8, '??', '??', '??',
        '??', 0x48, 0x8B, 0xD8, 0x48, 0x85, 0xC0
    };

    LPCBYTE lpGWorldPatternAddy = SearchForMaskedSignature(
        lpMemoryMappedFile,
        nFileSize,
        mGWorldPattern,
        MASK_SIZE(mGWorldPattern)
    );

    if (NULL == lpGWorldPatternAddy) {
        fprintf(
            stderr,
            "[-] Failed to find GWorld pattern in file.\n"
        );
        goto _RYUJI;
    }

    Offsets.GWorld = EvaluatePatternOffset(
        "GWorld",
        dwTextRVA,
        lpGWorldPatternAddy,
        lpMemoryMappedFile,
        7
    );

    LPCBYTE lpGObjectsPatternAddy = SearchForMaskedSignature(
        lpMemoryMappedFile,
        nFileSize,
        mGObjectsPattern,
        MASK_SIZE(mGObjectsPattern)
    );

    if (NULL == lpGObjectsPatternAddy) {
        fprintf(
            stderr,
            "[-] Failed to find GObjects pattern in file.\n"
        );
        goto _RYUJI;
    }

    Offsets.GObjects = EvaluatePatternOffset(
        "GObjects",
        dwTextRVA,
        lpGObjectsPatternAddy,
        lpMemoryMappedFile,
        6
    );

    LPCBYTE lpAppendStringPatternAddy = SearchForMaskedSignature(
        lpMemoryMappedFile,
        nFileSize,
        mAppendStringPattern,
        MASK_SIZE(mAppendStringPattern)
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

    LPCBYTE lpGNamesPatternAddy = (LPCBYTE) ((QWORD64) lpAppendStringPatternAddy + 0x20U);

    printf(
        " ** Assuming GNames pattern is at offset: 0x%llX (0x%llX)\n",
        (DWORD64) (lpGNamesPatternAddy - lpMemoryMappedFile),
        (DWORD64) (lpGNamesPatternAddy - lpMemoryMappedFile) + dwTextRVA
    );

    Offsets.GNames = EvaluatePatternOffset(
        "GNames",
        dwTextRVA,
        lpGNamesPatternAddy,
        lpMemoryMappedFile,
        3
    );

    LPCBYTE lpProcessEventFileOffset = SearchForMaskedSignature(
        lpMemoryMappedFile,
        nFileSize,
        mProcessEventPattern,
        MASK_SIZE(mProcessEventPattern)
    );

    if (NULL == lpProcessEventFileOffset) {
        fprintf(
            stderr,
            "[-] Failed to find ProcessEvent pattern in file.\n"
        );
        goto _RYUJI;
    }

    Offsets.ProcessEvent = (DWORD64) (lpProcessEventFileOffset - lpMemoryMappedFile) + dwTextRVA;

    LPCBYTE lpFindFunctionCheckedFileOffset = SearchForMaskedSignature(
        lpMemoryMappedFile,
        nFileSize,
        mFindFunctionCheckedPattern,
        MASK_SIZE(mFindFunctionCheckedPattern)
    );

    if (NULL == lpFindFunctionCheckedFileOffset) {
        fprintf(
            stderr,
            "[-] Failed to find FindFunctionChecked pattern in file.\n"
        );
        goto _RYUJI;
    }

    Offsets.FindFunctionChecked = (DWORD64) (lpFindFunctionCheckedFileOffset - lpMemoryMappedFile) + dwTextRVA;

    printf(
        "\n"
        " :: GObjects            : 0x%08llX\n"
        " :: AppendString        : 0x%08llX\n"
        " :: GNames              : 0x%08llX\n"
        " :: GWorld              : 0x%08llX\n"
        " :: ProcessEvent        : 0x%08llX\n"
        " :: FindFunctionChecked : 0x%08llX\n"
        "\n",
        Offsets.GObjects,
        Offsets.AppendString,
        Offsets.GNames,
        Offsets.GWorld,
        Offsets.ProcessEvent,
        Offsets.FindFunctionChecked
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