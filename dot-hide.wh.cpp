// ==WindhawkMod==
// @id              dot-hide
// @name            Dot Hide
// @description     Keep dot files and directories out of sight, Because it wouldn't happen in Linux...
// @version         1.0.0
// @author          Tomer Zait (realgam3)
// @github          https://github.com/realgam3
// @twitter         https://twitter.com/realgam3
// @homepage        https://realgam3.com/
// @include         explorer.exe
// @include         cmd.exe
// @include         pwsh.exe
// @include         powershell.exe
// ==/WindhawkMod==

// ==WindhawkModReadme==
/*
# Dot Hide
Dot Hide is a handy mod designed to bring the Linux-style hiding of dot files and directories to Windows.  
In Linux, files and directories starting with a dot ('.') are hidden by default, but this isn't the case in Windows.  
Dot Hide tackles this by automatically hiding these files and directories, creating a more streamlined and organized workspace.   

## Before
![Before](https://raw.githubusercontent.com/realgam3/dot-hide-wh/main/assets/img/before.png)

## After
![After](https://raw.githubusercontent.com/realgam3/dot-hide-wh/main/assets/img/after.png)

*/
// ==/WindhawkModReadme==

#include <string_view>
#include <winternl.h>

template <typename FileInfoType>
void HideFilesInDirectory(void* FileInformation, BOOLEAN ReturnSingleEntry) {
    FileInfoType* fileInformation = static_cast<FileInfoType*>(FileInformation);

    while (fileInformation) {
        std::wstring_view fileName(fileInformation->FileName, fileInformation->FileNameLength / sizeof(WCHAR));

        // fileName starts with . but not in [".", ".."]
        if (fileName.length() >= 2 && fileName[0] == '.' && (fileName[1] != '.' || fileName.length() > 2)) {
            Wh_Log(L"Class->Hide: %.*s", static_cast<int>(fileName.length()), fileName.data());
            fileInformation->FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
        }

        if (fileInformation->NextEntryOffset == 0 || ReturnSingleEntry) {
            break;
        }

        fileInformation = reinterpret_cast<FileInfoType*>(
            reinterpret_cast<LPBYTE>(fileInformation) + fileInformation->NextEntryOffset);
    }
}

void NtHideDirectoryFile(LPVOID FileInformation, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry) {
    switch (FileInformationClass) {
        case FileFullDirectoryInformation: {
            Wh_Log(L"Class: FileFullDirectoryInformation");
            HideFilesInDirectory<FILE_FULL_DIR_INFORMATION>(FileInformation, ReturnSingleEntry);
            break;
        }

        case FileBothDirectoryInformation: {
            Wh_Log(L"Class: FileBothDirectoryInformation");
            HideFilesInDirectory<FILE_BOTH_DIR_INFORMATION>(FileInformation, ReturnSingleEntry);
            break;
        }

        case FileIdBothDirectoryInformation: {
            Wh_Log(L"Class: FileIdBothDirectoryInformation");
            HideFilesInDirectory<FILE_ID_BOTH_DIR_INFORMATION>(FileInformation, ReturnSingleEntry);
            break;
        }

        default: {
            Wh_Log(L"Class: ID-%d", FileInformationClass);
            break;
        }
    }
}

typedef NTSTATUS(NTAPI* NtQueryDirectoryFile_t)(
    HANDLE                 FileHandle,
    HANDLE                 Event,
    PIO_APC_ROUTINE        ApcRoutine,
    PVOID                  ApcContext,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                  Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN                ReturnSingleEntry,
    PUNICODE_STRING        FileName,
    BOOLEAN                RestartScan
);
NtQueryDirectoryFile_t NtQueryDirectoryFile_Original;

NTSTATUS NtQueryDirectoryFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, LPVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, LPVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    Wh_Log(L"NtQueryDirectoryFile_Hook called");

    NTSTATUS status = NtQueryDirectoryFile_Original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    if (NT_SUCCESS(status)) {
        NtHideDirectoryFile(FileInformation, FileInformationClass, ReturnSingleEntry);
    }
    return status;
}

enum QUERY_FLAG : ULONG {
    SL_RESTART_SCAN = 0x00000001,
    SL_RETURN_SINGLE_ENTRY = 0x00000002,
    SL_INDEX_SPECIFIED = 0x00000004,
    SL_RETURN_ON_DISK_ENTRIES_ONLY = 0x00000008,
    SL_NO_CURSOR_UPDATE_QUERY = 0x00000010
};

typedef NTSTATUS(NTAPI* NtQueryDirectoryFileEx_t)(
    HANDLE                 FileHandle,
    HANDLE                 Event,
    PIO_APC_ROUTINE        ApcRoutine,
    PVOID                  ApcContext,
    PIO_STATUS_BLOCK       IoStatusBlock,
    PVOID                  FileInformation,
    ULONG                 Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    ULONG                  QueryFlags,
    PUNICODE_STRING        FileName
);
NtQueryDirectoryFileEx_t NtQueryDirectoryFileEx_Original;

NTSTATUS NtQueryDirectoryFileEx_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {
    Wh_Log(L"NtQueryDirectoryFileEx_Hook called");

    NTSTATUS status = NtQueryDirectoryFileEx_Original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
    if (NT_SUCCESS(status)) {
        NtHideDirectoryFile(FileInformation, FileInformationClass, QueryFlags & SL_RETURN_SINGLE_ENTRY);
    }
    return status;
}

// The mod is being initialized, load settings, hook functions, and do other
// initialization stuff if required.
BOOL Wh_ModInit() {
    Wh_Log(L"Init");

    HMODULE ntdllModule = LoadLibrary(L"ntdll.dll");

    NtQueryDirectoryFile_t NtQueryDirectoryFile = (NtQueryDirectoryFile_t)GetProcAddress(ntdllModule, "NtQueryDirectoryFile");
    Wh_SetFunctionHook((void*)NtQueryDirectoryFile,
                       (void*)NtQueryDirectoryFile_Hook,
                       (void**)&NtQueryDirectoryFile_Original);

    NtQueryDirectoryFileEx_t NtQueryDirectoryFileEx = (NtQueryDirectoryFileEx_t)GetProcAddress(ntdllModule, "NtQueryDirectoryFileEx");
    Wh_SetFunctionHook((void*)NtQueryDirectoryFileEx,
                       (void*)NtQueryDirectoryFileEx_Hook,
                       (void**)&NtQueryDirectoryFileEx_Original);

    return TRUE;
}

// The mod is being unloaded, free all allocated resources.
void Wh_ModUninit() {
    Wh_Log(L"Uninit");
}
