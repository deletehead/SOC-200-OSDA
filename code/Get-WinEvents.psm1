 ###
# Notes:
# - REMEMBER: Use a 24-hour clock when specifying times. Gets me every time.
###

# Get date to query (current time)
function Get-LogTStamp {
    param (
        $seconds
    )
    
    if ($seconds -eq $null) {
        $seconds = 10
    }
    
    $d      = Get-Date
    $dEnd   = '{0:MM/dd/yyyy HH:mm:ss}' -f $d
    $dStart = '{0:MM/dd/yyyy HH:mm:ss}' -f $d.AddSeconds(-$seconds)
    $out =  "`"$dStart`" `"$dEnd`""
    return $out.ToString()
}

# Get a Sysmon event with a specific ID and time
function Get-SysmonEvent {
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-Sysmon/Operational"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }
    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    Get-WinEvent -FilterHashtable $filters
}

# Run Get-SysmonEvent (Time - $seconds)
function Get-SysmonEventT {
    param (
        $seconds
    )

    if ($seconds -eq $null) {
        $seconds = 10
    }
    $times = Get-LogTStamp $seconds
    $cmd = "Get-SysmonEvent `$null " + $times
    write-host "[*] Running: $cmd"
    IEX $cmd
}

# Get a Security event with a specific ID and time
function Get-SecurityEvent {
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Security"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }
    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    Get-WinEvent -FilterHashtable $filters
}

# Run Get-SecurityEvent (Time - $seconds)
function Get-SecurityEventT {
    param (
        $seconds
    )

    if ($seconds -eq $null) {
        $seconds = 10
    }
    $times = Get-LogTStamp $seconds
    $cmd = "Get-SecurityEvent `$null " + $times
    write-host "[*] Running: $cmd"
    IEX $cmd
}

# Get-SecurityEvent 4625 "5/6/2021 00:00:00" "5/7/2021 00:00:00"
function Get-FailedLogonEvent {
    param (
        $start,
        $end
    )
    $filters = @{LogName = "Security"}
    
    # Setting static 4625 for failed logon event
    $filters.ID = 4625

    if ($start -ne $null) {
        $filters.StartTime = $start
    }
    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    Get-WinEvent -FilterHashtable $filters
    
    ### EXAMPLE: Use Get-FailedLogonEvent and filter the output into a nice readable table:
    ##  Get-FailedLogonEvent "3/13/2023 15:15:00" "3/13/2023 15:15:01" | 
    #     Format-List  TimeCreated, @{Label = "Logon Type"; Expression = {$_.properties[10].value}}, @{Label = "Status"; Expression = {'{0:X8}' -f $_.properties[7].value}}, 
    #     @{Label = "Substatus"; Expression = {'{0:X8}' -f $_.properties[9].value}}, @{Label = "Target User Name"; Expression = {$_.properties[5].value}}, 
    #     @{Label = "Workstation Name"; Expression = {$_.properties[13].value}}, @{Label = "IP Address"; Expression = {$_.properties[19].value}} 
} 

# Run Get-FailedLogonEvent (Time - $seconds)
function Get-FailedLogonEventT {
    param (
        $seconds
    )

    if ($seconds -eq $null) {
        $seconds = 10
    }
    $times = Get-LogTStamp $seconds
    $cmd = "Get-FailedLogonEvent `$null " + $times
    write-host "[*] Running: $cmd"
    IEX $cmd
}

function Get-PSLogEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-PowerShell/Operational"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }
    if ($end -ne $null) {
        $filters.EndTime = $end
    }

    Get-WinEvent -FilterHashtable $filters
}

function Get-WDLogEvent {
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-Windows Defender/Operational"}

    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }

    Get-WinEvent -FilterHashtable $filters
}

# Run Get-PSLogEvent (Time - $seconds)
#   function Get-PSLogEventT { ... } 
#   This one failed.
