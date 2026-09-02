# Echoes in the Wire Writeup

2nd September 2026

Prepared by: handlehere

Machine Author(s): handlehere

Difficulty:Easy

## Scenario

```
Security Operations Center (SOC) alerts detected abnormal outbound network connections originating from an internal Linux workstation. Initial triage revealed that an employee account was compromised via SSH brute-force, after which an attacker uploaded and executed a suspicious binary named invoice_update.bin. By analyzing host authentication logs, web server access logs, network packet captures, and the executable itself, we reconstruct the complete attack timeline and identify key indicators of compromise (IOCs).

```

## Artifacts Provided

* `auth.log`
* `access.log`
* `capture.pcap`
* `invoice_update.bin` - *962ddc62ec87c8005b63fb7aa59ca544b8ee76f082e6efc7c10b2a7bd2dbd3f7*
* `invoice_update.bin.sha256`
* `recovered_note.txt`

## Initial Analysis

Triage of the provided package involves analyzing authentication logs (`auth.log`), web server activity (`access.log`), full packet captures (`capture.pcap`), and static inspection of the executable (`invoice_update.bin`).

### Log & Binary Analysis

Inspection of authentication logs shows initial unauthorized access via SSH password brute-forcing against the user `employee`. Following successful access, the binary `invoice_update.bin` was staged and executed on the host.

Running static string extraction on `invoice_update.bin` reveals cleartext network infrastructure references, user-agent details, and file targets:

```text
System update service
invoice_update
/usr/bin/curl
telemetry.example.org
updates-check.example.net
/api/v1/checkin
employee_backup.txt
cdn.example.org

```

### Attack Summary Sequence

```
[198.51.100.42] (Attacker)
       │
       ├─── 1. SSH Brute Force ─────────────────► Workstation (employee user)
       ├─── 2. Fetch Payload ───────────────────► GET /staging/invoice_update.bin
       │
[Workstation] Executing invoice_update.bin
       │
       ├─── 3. DNS Telemetry Check ─────────────► telemetry.example.org
       ├─── 4. Secondary C2 Beacon ─────────────► updates-check.example.net/api/v1/checkin
       └─── 5. Data Staging / Exfiltration ────► cdn.example.org/employee_backup.txt

```

## Questions

1. What is the SHA256 hash of the malicious binary 'invoice_update.bin'?
`962ddc62ec87c8005b63fb7aa59ca544b8ee76f082e6efc7c10b2a7bd2dbd3f7`

To calculate the hash directly from the command line, run `sha256sum`:

```bash
sha256sum artifacts/invoice_update.bin

```

Alternatively, inspect the accompanying hash manifest:

```bash
cat artifacts/invoice_update.bin.sha256

```

2. Which external IP address performed the successful SSH brute-force attack against the workstation?
`198.51.100.42`

Investigate system authentication events recorded in `auth.log` by searching for successful password acceptances:

```bash
grep "Accepted password" artifacts/auth.log

```

Log output:

```text
Oct 24 08:12:01 workstation sshd[1420]: Failed password for invalid user admin from 198.51.100.42 port 41122 ssh2
Oct 24 08:12:03 workstation sshd[1422]: Failed password for invalid user root from 198.51.100.42 port 41124 ssh2
Oct 24 08:12:05 workstation sshd[1425]: Failed password for employee from 198.51.100.42 port 41126 ssh2
Oct 24 08:12:08 workstation sshd[1428]: Accepted password for employee from 198.51.100.42 port 41130 ssh2

```

3. What is the primary domain contacted by the binary during its initial telemetry check?
`telemetry.example.org`

Extract printable strings embedded inside `invoice_update.bin` or inspect DNS requests inside `capture.pcap` using `tshark`:

```bash
tshark -r artifacts/capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

```

The initial DNS query emitted by the infected host points to `telemetry.example.org`.

4. What URI endpoint path is used for secondary C2 check-ins?
`/api/v1/checkin`

Analyze web server requests in `access.log` or filter HTTP traffic in Wireshark:

```bash
grep "GET" artifacts/access.log

```

Log output:

```text
198.51.100.42 - - [24/Oct/2026:08:12:15 +0000] "GET /staging/invoice_update.bin HTTP/1.1" 200 128 "-" "curl/7.68.0"
192.168.1.105 - - [24/Oct/2026:08:14:30 +0000] "GET /api/v1/checkin HTTP/1.1" 200 45 "-" "curl/7.68.0"

```

Wireshark display filter:

```http
http.request.method == "GET" && http.host == "updates-check.example.net"

```

5. What external domain was used to stage and exfiltrate the backup archive 'employee_backup.txt'?
`cdn.example.org`

Filter HTTP traffic in `capture.pcap` for references to `employee_backup.txt`:

```bash
tshark -r artifacts/capture.pcap -Y 'http contains "employee_backup.txt"' -T fields -e http.host -e http.request.uri

```

Output:

```text
cdn.example.org    /employee_backup.txt

```

Corroborating this with embedded binary strings confirms `cdn.example.org` as the host used for staging and exfiltration.
