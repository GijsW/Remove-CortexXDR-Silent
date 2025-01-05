# Remove-CortexXDR-Silent - README
 Silently uninstalls Cortex XDR (and Traps) with advanced cleanup and logging.

## Overview

This PowerShell script **silently uninstalls** Cortex XDR (and Traps) from Windows systems, performing a comprehensive cleanup of leftover services, registry keys, and directories. It produces **no console output**, and logs all actions to a specified file.

---

## Disclaimer

This script is made available **as-is**, without warranty of any kind, under the **MIT License**. Use of this script is **at your own risk**, and the author/maintainer **accepts no responsibility** for any potential issues, damages, or loss arising from its use.

---

## Features

1. **Silent Uninstall**  
   - Detects if Cortex XDR/Traps is installed and uses registry uninstall data for removal.  
   - If you do not provide a password, the script defaults to `"DefaultXDRPassword"`.

2. **Advanced Cleanup**  
   - Terminates and removes leftover services, registry entries, and file-system directories associated with Cortex XDR/Traps.

3. **Logging**  
   - Writes all actions to a **log file** (default: `C:\Temp\CortexXDRUninstall.log`).  
   - If `-VerboseOutput` is used, additional detail is added to that log (still no console output).

4. **Exit Codes**  
   - **0** – Successful removal (or Cortex XDR was not found).  
   - **1** – Could not set up log directory (script exits early).  
   - **2** – Script not run as Administrator.  
   - **3** – Partial or unsuccessful removal (manual intervention may be required).

---

## Usage

```powershell
# Basic usage (uses the default password and default log file):
.\remove-cortex_silent.ps1

# With a custom password and custom log file:
.\remove-cortex_silent.ps1 -CortexUninstallPassword "<password>" -LogFile "C:\Logs\XDR_Uninstall.log"
```

### Parameters

- **CortexUninstallPassword**  
  - Optional, String.  
  - If Cortex XDR requires an uninstall password, specify it here.  
  - If omitted, `"DefaultXDRPassword"` is used.

- **LogFile**  
  - Optional, String.  
  - Path to the file where logs should be written.  
  - Defaults to `C:\Temp\CortexXDRUninstall.log`.

- **VerboseOutput**  
  - Optional, Switch.  
  - Provides extra debug/log detail in the log file.

---

## Prerequisites

1. **Run as Administrator**  
   - The script checks for elevated privileges and exits if not run as Administrator.

2. **Test in a Controlled Environment**  
   - Validate the script on a small set of test machines to ensure it meets your requirements before large-scale deployment.

---

## Deployment Methods

You can push this script via:

- **Group Policy** (Computer Startup Script).  
- **SCCM**, **Intune**, or **RMM** solutions that allow running PowerShell scripts in the **system** or **administrator** context.

No console output is displayed; refer to the log file for progress and error messages.

---

## License and Disclaimer

This script is provided under the **MIT License**. Use of this script is **at your own risk** — you assume all responsibility for any outcomes. The script’s author/maintainer is **not responsible** for any errors, damages, or losses incurred from its use.

> **MIT License** (excerpt):
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, and/or distribute copies of the Software, subject to the following conditions: ... THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
