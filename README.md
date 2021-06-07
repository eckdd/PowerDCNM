
[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/eckdd/PowerDCNM)

# PowerDCNM
PowerShell REST client for Cisco Data Center Network Manager (DCNM) version 11

The functions in this module invoke REST calls to the DCNM API enabling the bulk creation and management of objects and policies.

USE AT YOUR OWN RISK! 
This module is still under development and any feature may or may not work as intended.
Please only use in lab/development environments unless you have a strong understanding of PowerShell and the REST API.
I am not responsible for any damages or downtime caused by the use of these modules. 

This module was written primarily in PowerShell version 6 is intended to be cross-platform--same behavior is expected on Linux/Mac as on Windows 10

# Requirements
This module was developed in PowerShell version 6 on Windows 10.
This module should be backwards compatible with PowerShell version 5.1
Data Center Network Manager 11
# Setup/Update with PSGallery (All OSes)
Install:

Install-Module PowerDCNM

Update:

Update-Module PowerDCNM

# Setup/Update (Windows)

Paste the following in PowerShell:
#
md ($env:PSModulePath -split ';')[0] -ErrorAction Ignore

cd ($env:PSModulePath -split ';')[0]

Start-BitsTransfer -Source https://github.com/eckdd/PowerDCNM/archive/master.zip -Destination .

Expand-Archive -Path .\master.zip

md .\PowerDCNM -ErrorAction Ignore

copy ".\master\PowerDCNM-master\\*" -Container PowerDCNM -Force

del .\master\ -Force -Recurse

del .\master.zip

Import-Module PowerDCNM -Force
#
#
# Setup/Update (Mac/Linux)

Paste the following in PowerShell:
#
md ($env:PSModulePath -split ':')[0]

cd ($env:PSModulePath -split ':')[0]

wget https://github.com/eckdd/PowerDCNM/archive/master.zip

Expand-Archive -Path ./master.zip

md PowerDCNM

copy ./master/PowerDCNM-master/* -Container PowerDCNM -Force

del .\master\ -Force -Recurse

del .\master.zip

Import-Module PowerDCNM -Force
#
#
# Usage 
NOTE: You may need to update the PowerShell execution policy with the following:

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser

Begin by generating  an Auth Access Token with the New-DCNMAuthToken function. This will prompt for the DCNM host URL and credentials with API access. Once ran, a token valid for 60 minutes will be stored in the current PowerShell session environment and all other functions can be used without specifying the token, domain, or DCNM host.
Get-Command -Module PowerDCNM will display all the functions available in this module. Use Get-Help with the name of the function followed by -Examples to see examples of usage.

More functions will continue to be added in the future, and usage of existing functions is subject to change. Pay attention to the release notes and current issues page for information on new features and bugs.
