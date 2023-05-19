# ELK: KQL Queries & Detections
## KQL Notes
- KQL example syntax:
```
field1: value1 and field2:"value 2" and not field3: value3* and field4.subfield <= 30
```
- Windows events - Sysmon example:
```
host.hostname: "appsrv01" and data_stream.dataset: "windows.sysmon_operational" and process.name: "svchost.exe" and event.code:"1"
```
- Web requests:
```
"apache-access" and host.hostname: "web01" and not source.ip: 127.0.0.1
```
- Snort events:
```
tags: "snort.log" and network.type: "ipv4"
```
- OSQuery generic:
```
SELECT field1, field2, fieldx FROM table1 WHERE field1 = value1 AND field2 like '%value2%';
```
- OSQuery example:
```
select directory, filename from file where path like 'C:\Users\%\Desktop\%' and filename like '%.txt';
```

## Initial Access
### Web Attacks
- SQL injection:

- LFI/RFI:

- Command injection:

- Malicious file upload:

### Credential Attacks
- SSH:
```
## SSH login success; select "user.name". Observer stats on source IP.
event.action:"ssh_login" and event.outcome:success
```

## Privilege Escalation

## Persistence

## Lateral Movement
