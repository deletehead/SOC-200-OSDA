function Get-SysmonEvent {
    Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
}
