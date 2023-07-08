# Ternimator
A nim re-write of [Terminator](https://github.com/ZeroMemoryEx/Terminator/) that allows for loading the driver via either service creation or NtLoadDriver api call. The driver is embeded into the executable and will be dropped to disk. The executable also embeds and drops `kernel_exec.exe` which exploits a different vuln in the zemana driver to elevate to SYSTEM ([CVE-2021-31728](https://github.com/irql0/CVE-2021-31728/tree/master))

Build:
```
nimble build
```
<br>
Cleanup currently does not work for either the service or the NtLoadDriver methods...
<br>
Manualy cleanup the service:
```
sc stop zTerm
sc delete zTerm
```
<br>
Manualy cleanup the NtLoadDriver:
```
Restart the system lol
```