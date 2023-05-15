# ELK: KQL Queries & Detections
## KQL Notes
- KQL example syntax:
```
field1: value1 and field2: "value 2" and not field3: value3* and field4.subfield <= 30
```
- Windows events - Sysmon example:
```
host.hostname: "appsrv01" and data_stream.dataset : "windows.sysmon_operational" and process.name : "svchost.exe" and event.code: "1"
```
- Web requests:
```
"apache-access" and host.hostname: "web01" and not source.ip: 127.0.0.1
```

## Initial Access

## Privilege Escalation

## Persistence

## Lateral Movement
