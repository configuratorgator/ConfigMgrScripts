# ConfigMgrScripts
A bunch of miscellaneous scripts related to ConfigMgr.

# ConfigMgr AD Cleanup
This PowerShell script will compare all enabled computer objects in Active Directory against the list of devices in ConfigMgr and will remove any devices found in ConfigMgr that do not exist in Active Directory.  It will not make changes to Active Directory.  It supports a user-defined exclusion list and automatically excludes the built-in devices (i.e. x64 Unknown Computer).

# Zoom.zip
This ZIP file contains two CAB files that represent ConfigMgr Configuration Items.

# Zoom.zip: Zoom - Per System.cab
This CAB file represents a ConfigMgr Configuration item that detects installations of Zoom on the system.  It will report on installed plugins (system-wide installers) and whether any user profile contains Zoom.  If deployed in Remediate mode it will remove only the system-wide installations.

# Zoom.zip: Zoom - Per User.cab
This CAB file represents a ConfigMgr Configuration Item that detects installations of Zoom in user profiles.  It will report which user profiles have Zoom installed.  If deployed in Remediate mode it will remove Zoom by running the uninstaller as the signed-in user.
