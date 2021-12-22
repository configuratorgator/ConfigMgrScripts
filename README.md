# ConfigMgrScripts
A bunch of miscellaneous scripts related to ConfigMgr.

# ConfigMgr AD Cleanup
This PowerShell script will compare all enabled computer objects in Active Directory against the list of devices in ConfigMgr and will remove any devices found in ConfigMgr that do not exist in Active Directory.  It will not make changes to Active Directory.  It supports a user-defined exclusion list and automatically excludes the built-in devices (i.e. x64 Unknown Computer).

# Update ConfigMgr Certificates
This PowerShell script will update the PKI certificates throughout a ConfigMgr environment, provided the prequisites/assumptions are met and the certificates are not yet expired.

# Zoom.zip
This ZIP file contains two CAB files that represent ConfigMgr Configuration Items.

# Zoom.zip: Zoom - Per System.cab
This CAB file represents a ConfigMgr Configuration item that detects installations of Zoom on the system.  It will report on installed plugins (system-wide installers) and whether any user profile contains Zoom.  If deployed in Remediate mode it will remove only the system-wide installations.  The script does not search the system for Zoom installations, rather it uses GUIDs that you define as ones you want to be found/removed.  The GUIDs contained in the script's variable block are from inventory data in one of my environments.  You can easily find this data in your environment and update the GUID list as needed.

# Zoom.zip: Zoom - Per User.cab
This CAB file represents a ConfigMgr Configuration Item that detects installations of Zoom in user profiles.  It will report which user profiles have Zoom installed.  If deployed in Remediate mode it will remove Zoom by running the uninstaller as the signed-in user.
