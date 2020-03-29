# ConfigMgrScripts
A bunch of miscellaneous scripts related to ConfigMgr.

# ConfigMgr AD Cleanup
This PowerShell script will compare all enabled computer objects in Active Directory against the list of devices in ConfigMgr and will remove any devices found in ConfigMgr that do not exist in Active Directory.  It will not make changes to Active Directory.  It supports a user-defined exclusion list and automatically excludes the built-in devices (i.e. x64 Unknown Computer).
