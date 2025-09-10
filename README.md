# Invoke-SMBScan

A **PowerShell-based SMB share scanner** inspired by the original [smbmap](https://github.com/ShawnDEvans/smbmap) tool (Linux-only). This script is built entirely in PowerShell to provide similar functionality natively on Windows. It allows penetration testers to quickly enumerate SMB shares, test read/write permissions, and extract sample directory/file listings.

Unlike the Linux-only `smbmap`, this PowerShell version works directly on Windows environments and saves significant time when testing networks where SMB access is critical.

---

## Features

* **CIDR, comma-separated, or file-based target input**
* **TCP/445 reachability check** (to avoid wasting time on dead/filtered hosts)
* **Share enumeration** (excluding default admin shares)
* **Read permission checks** and listing of **sample folders/files**
* **Optional write test** (create and delete temporary file)
* **CSV export** of all results (including failures)

---

## Prerequisites

* Windows host with PowerShell (5.1 or above)
* Valid **domain credentials** for best results
* **Initial foothold** (e.g., compromised user context or valid creds) to maximize accessible shares

---

## Usage

```powershell
# Run against a CIDR range
powershell -ExecutionPolicy Bypass -File .\Invoke-SMBScan.ps1 -Targets "10.7.1.0/24" -ListDepth 0

# Run with input file, domain creds, deeper listing, and write test
powershell -ExecutionPolicy Bypass -File .\Invoke-SMBScan.ps1 `
  -InputFile .\hosts.txt `
  -Domain ACME -Username pentest -Password 'Winter2025!' `
  -ListDepth 1 -TestWrite -OutCsv .\shares.csv
```

---

## Output Format

All results are saved in a CSV file (default: `smbscan_results.csv`). Each row contains:

| Column          | Description                                                         |
| --------------- | ------------------------------------------------------------------- |
| **IP**          | Target IP address                                                   |
| **Share**       | Share name (blank if none)                                          |
| **UNC**         | Full UNC path (\IP\Share)                                           |
| **Readable**    | True/False — can we list content?                                   |
| **Writable**    | True/False — can we create a file?                                  |
| **Status**      | ok / error / access\_denied / no\_smb\_listener / system\_error\_53 |
| **Error**       | Error message if access failed                                      |
| **SampleDirs**  | Semicolon-separated sample directory names                          |
| **SampleFiles** | Semicolon-separated sample file names                               |

---

## Example CSV Output

```csv
IP,Share,UNC,Readable,Writable,Status,Error,SampleDirs,SampleFiles
10.7.1.6,Public,\\10.7.1.6\Public,True,False,ok,,"Docs;Finance","report1.docx;data.csv"
10.7.1.15,,,False,False,no_smb_listener,tcp/445 closed or filtered,,
```

---

## Benefits

* Native Windows support — no need for WSL or Cygwin
* Faster results thanks to built-in 445 probing
* CSV output helps integrate into reporting pipelines
* Saves significant enumeration time during **internal pentests** and **post-exploitation footholds**

---

## Credits

* Inspired by the excellent [smbmap](https://github.com/ShawnDEvans/smbmap) Linux tool
* Rewritten fully in PowerShell for Windows-based assessments
