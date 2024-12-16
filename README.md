# Release Information 

- **Version**: 1.0.0 
- **Certified**: No 
- **Publisher**: Fortinet 
- **Compatible Version**: FortiSOAR 7.4.0 and later 

# Overview 

Security flaws in Mitel MiCollab, CVE-2024–35286, CVE-2024–41713, and an arbitrary file read zero-day (still without a CVE number) have been found, putting many organizations at risk. These vulnerabilities allow attackers to bypass authentication and access files on affected servers, revealing sensitive information that could expose organizations to serious security risks. 

 The **Outbreak Response - Mitel MiCollab Unauthorized Access Attack** solution pack works with the Threat Hunt rules in [Outbreak Response Framework](https://github.com/fortinet-fortisoar/solution-pack-outbreak-response-framework/blob/release/2.0.0/docs/background-information.md#threat-hunt-rules) solution pack to conduct hunts that identify and help investigate potential Indicators of Compromise (IOCs) associated with this vulnerability within operational environments of *FortiSIEM*, *FortiAnalyzer*, *QRadar*, *Splunk*, and *Azure Log Analytics*.

 The [FortiGuard Outbreak Page](https://www.fortiguard.com/outbreak-alert/mitel-micollab-unauthorized-access) contains information about the outbreak alert **Outbreak Response - Mitel MiCollab Unauthorized Access Attack**. 

## Background: 

Mitel MiCollab is a popular solution that combines voice calling, video calling, chat, file sharing, screen sharing, and more into one platform for enterprise communications. 

-A SQL injection vulnerability, CVE-2024-35286, has been identified in NuPoint Unified Messaging (NPM) component of Mitel MiCollab which, if successfully exploited, could allow a malicious actor to conduct a SQL injection attack.   

-A path traversal vulnerability, CVE-2024-41713, in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab could allow an unauthenticated attacker to conduct a path traversal attack due to insufficient input validation. 

-An arbitrary file read zero-day, without a CVE number. The zero-day can only be exploited by authenticated attackers.

A recently released Proof-of-Concept (PoC) exploit demonstrates how attackers can chain these vulnerabilities to compromise systems, and steal sensitive data to the organizations. 

## Announced: 

Mitel has released fixes for the vulnerabilities (CVE-2024-35286 and CVE-2024-41713 ). Organizations that have not implemented the latest patch are advised to do so immediately and monitor vendor advisories for further patch releases and information. 

## Latest Developments: 

December 11, 2024: Proof-of-Concept (PoC) exploit and technical details released by watchtowr.
https://labs.watchtowr.com/where-theres-smoke-theres-fire-mitel-micollab-cve-2024-35286-cve-2024-41713-and-an-0day/

December 10, 2024: FortiGuard released Threat Signal Report
https://www.fortiguard.com/threat-signal-report/5599/mitel-micollab-unauthorized-access-cve-2024-35286-cve-2024-41713

October 9, 2024: Mitel Product Security Advisory MISA-2024-0029
MiCollab Path Traversal Vulnerability
https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029

May 23, 2024: Mitel Product Security Advisory 24-0014
MiCollab SQL Injection Vulnerability
https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-24-0014 

# Next Steps
 | [Installation](./docs/setup.md#installation) | [Configuration](./docs/setup.md#configuration) | [Usage](./docs/usage.md) | [Contents](./docs/contents.md) | 
 |--------------------------------------------|----------------------------------------------|------------------------|------------------------------|