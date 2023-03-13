###
# Notes:
# - REMEMBER: Use a 24-hour clock when specifying times. Gets me every time.
###

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

