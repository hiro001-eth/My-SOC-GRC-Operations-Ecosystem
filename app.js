/* ===============================================================================
   SOC & GRC OPERATIONS ECOSYSTEM - INTERACTIVE VISUALIZER LOGIC
   DATA STORE & REAL-TIME INSPECTOR ENGINE
   =============================================================================== */

const ECOSYSTEM_DATA = {
  domains: [
    {
      id: "01",
      name: "01 - Data Sources and Ingestion",
      shortName: "Data Ingestion",
      category: "Ingestion Layer",
      description: "Master pipeline architecture cataloging log sources, endpoint telemetry configs (Sysmon), and collector agents (Fluent Bit, Logstash, Vector).",
      files: [
        {
          path: "01-DATA-SOURCES-AND-INGESTION/README.md",
          name: "README.md",
          type: "markdown",
          narrative: "Serves as the master pipeline architecture guide. Documents collector topologies, log collection strategies, and endpoint agent deployment standards.",
          connections: ["02-NORMALIZATION-AND-PARSING/README.md", "03-DETECTION-ENGINEERING/README.md"],
          code: `<!-- 
SEGMENT: 01-DATA-SOURCES-AND-INGESTION / Architecture Guide
PURPOSE: Master pipeline architecture guide for endpoint, cloud, network, and application log ingestion topology.
CONNECTED WORKFLOWS:
  - Connects log collector configurations to 02-NORMALIZATION-AND-PARSING/ and analytics in 03-DETECTION-ENGINEERING/
-->
# Readme
Master pipeline architecture guide for log ingestion topology across Windows, Cloud, and Linux sources.`
        },
        {
          path: "01-DATA-SOURCES-AND-INGESTION/collectors-and-agents/fluentbit/fluent-bit.conf",
          name: "fluent-bit.conf",
          type: "conf",
          narrative: "Configures Fluent Bit log forwarder to collect system and security logs from endpoint agents and stream them to Logstash / SIEM pipelines.",
          connections: ["02-NORMALIZATION-AND-PARSING/field-dictionary.md"],
          code: `[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf

[INPUT]
    Name          syslog
    Path          /var/log/syslog
    Tag           syslog.general

[OUTPUT]
    Name          es
    Match         *
    Host          elasticsearch.internal.soc
    Port          9200
    Index         soc-telemetry-syslog`
        },
        {
          path: "01-DATA-SOURCES-AND-INGESTION/sample-logs/winlogbeat-config.yml",
          name: "winlogbeat-config.yml",
          type: "yaml",
          narrative: "Defines the Winlogbeat log replay configuration for ingesting real attack EVTX log samples into an Elasticsearch ingestion pipeline.",
          connections: ["03-DETECTION-ENGINEERING/test-data/windows-evtx/"],
          code: `winlogbeat.event_logs:
  - name: "\${EVTX_FILE_PATH:C:\\\\Logs\\\\*.evtx}"
    no_seek: true
    ignore_older: 720h

output.elasticsearch:
  hosts: ["\${ELASTICSEARCH_HOST:localhost:9200}"]
  username: "\${ELASTIC_USER:elastic}"
  password: "\${ELASTIC_PASSWORD:changeme}"
  index: "winlogbeat-attack-samples-%{+yyyy.MM.dd}"`
        },
        {
          path: "01-DATA-SOURCES-AND-INGESTION/log-inventory/sysmon-configs/sysmonconfig-export.xml",
          name: "sysmonconfig-export.xml",
          type: "xml",
          narrative: "Canonical Sysmon configuration file defining rules for capturing process creation (Event 1), network connections (Event 3), and LSASS memory access (Event 10).",
          connections: ["03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml"],
          code: `<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Create (Event ID 1) -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">cmd.exe</CommandLine>
      <CommandLine condition="contains">powershell.exe</CommandLine>
    </ProcessCreate>
    <!-- Process Access (Event ID 10) -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\\Windows\\system32\\lsass.exe</TargetImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>`
        }
      ]
    },
    {
      id: "02",
      name: "02 - Normalization and Parsing",
      shortName: "Normalization",
      category: "Processing Layer",
      description: "Enterprise taxonomy layer translating vendor-specific raw logs into canonical schemas (ECS & OCSF) via Grok parsers and field dictionaries.",
      files: [
        {
          path: "02-NORMALIZATION-AND-PARSING/field-dictionary.md",
          name: "field-dictionary.md",
          type: "markdown",
          narrative: "The central dictionary mapping Sysmon, Windows Event, and CloudTrail raw attributes to unified ECS terms like process.name and user.name.",
          connections: ["03-DETECTION-ENGINEERING/kql/process-execution/suspicious_cmd_parent_child.kql", "05-THREAT-HUNTING/hunt-queries/hunting_rare_user_agents.kql"],
          code: `# Enterprise Field Dictionary Taxonomy
| Vendor Source Field | Unified SOC Field Term | ECS Mapping | OCSF Mapping |
| --- | --- | --- | --- |
| Sysmon Image | process.executable | process.name | process.file.name |
| Sysmon ParentImage | process.parent.executable | process.parent.name | process.parent_process.name |
| EventID 4688 NewProcessName | process.name | process.executable | process.name |
| TargetFilename | file.path | file.path | file.path |`
        },
        {
          path: "02-NORMALIZATION-AND-PARSING/custom-parsers/syslog-parsers/palo-alto-firewall.grok",
          name: "palo-alto-firewall.grok",
          type: "grok",
          narrative: "Grok parser pattern extracting network session observables, source IPs, destination ports, and threat flags from Palo Alto firewall syslogs.",
          connections: ["03-DETECTION-ENGINEERING/suricata-snort/network-signatures/emerging_threats_c2.rules"],
          code: `PALOALTO_TRAFFIC %{TIMESTAMP_ISO8601:log_time},%{WORD:serial_number},%{WORD:type},%{WORD:subtype},%{IP:source_ip},%{IP:destination_ip},%{INT:source_port},%{INT:destination_port}`
        }
      ]
    },
    {
      id: "03",
      name: "03 - Detection Engineering",
      shortName: "Detection Engineering",
      category: "Detection Layer",
      description: "Detection-as-Code ecosystem containing Sigma rules, KQL queries, YARA rules, Suricata signatures, Atomic Red Team tests, and tuning logs.",
      files: [
        {
          path: "03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml",
          name: "proc_creation_win_mimikatz_cmdline.yml",
          type: "yaml",
          narrative: "Production Sigma rule detecting command-line credential dumping tools (Mimikatz, sekurlsa::logonpasswords, lsadump::sam). Mapped to MITRE T1003.",
          connections: ["04-ALERT-LIFECYCLE-AND-TRIAGE/triage-guides/tier1-triage-checklist.md", "06-THREAT-INTELLIGENCE-AND-IOCS/mitre-attack-mapping/coverage-matrix.md"],
          code: `title: Credential Dumping via Mimikatz Command Line Arguments
id: a64175b5-779d-4e93-9c86-13a8549326eb
status: test
description: Detects process creation events containing command line flags associated with Mimikatz credential dumping.
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmdline:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
            - 'privilege::debug'
    condition: selection_cmdline
level: high`
        },
        {
          path: "03-DETECTION-ENGINEERING/kql/privilege-escalation/lsass_memory_dumping.kql",
          name: "lsass_memory_dumping.kql",
          type: "kql",
          narrative: "Microsoft Sentinel KQL query searching for Sysmon Event ID 10 process access events targeting lsass.exe with read memory rights (0x1000 or 0x1410).",
          connections: [".github/workflows/kql-lint-check.yml", "07-INCIDENT-RESPONSE-AND-SOAR/incident-playbooks/credential-dumping-playbook.md"],
          code: `Sysmon
| where EventID == 10
| where TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1000", "0x1410", "0x1F0FFF")
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, SourceProcessId`
        },
        {
          path: "03-DETECTION-ENGINEERING/detection-testing/atomic-red-team-tests/T1003.001-lsass-dump-test.yaml",
          name: "T1003.001-lsass-dump-test.yaml",
          type: "yaml",
          narrative: "Atomic Red Team test definition simulating an LSASS dump using comsvcs.dll to validate that detection rules trigger correctly.",
          connections: ["03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml"],
          code: `attack_technique: T1003.001
display_name: 'LSASS Memory Dump via Comsvcs.dll'
atomic_tests:
  - name: Dump LSASS.exe using comsvcs.dll
    auto_generated_guid: 82512f45-a7b2-4d04-9c44-59e512403657
    executor:
      name: powershell
      command: |
        rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Windows\\Temp\\lsass.dmp full`
        }
      ]
    },
    {
      id: "04",
      name: "04 - Alert Lifecycle and Triage",
      shortName: "Alert Triage",
      category: "Operations Layer",
      description: "Framework governing alert classification, SLA resolution windows (P1-P4), Tier 1-3 checklists, and shift handover procedures.",
      files: [
        {
          path: "04-ALERT-LIFECYCLE-AND-TRIAGE/severity-matrix-and-sla/sla-definitions.md",
          name: "sla-definitions.md",
          type: "markdown",
          narrative: "Defines SOC incident response timelines: P1 Critical (15 min response, 1 hr containment), P2 High (30 min response), down to P4 Info.",
          connections: ["10-METRICS-KPI-AND-REPORTING/soc-kpis/mttd-mttr-dashboard-spec.md"],
          code: `# Incident Severity Matrix & SLA Resolution Targets
| Severity Level | Response SLA | Containment SLA | Escalation Target |
| --- | --- | --- | --- |
| P1 - Critical | 15 Minutes | 1 Hour | Tier 3 Lead & CISO |
| P2 - High | 30 Minutes | 4 Hours | Tier 2 IR Lead |
| P3 - Medium | 2 Hours | 24 Hours | Tier 1 Analyst |
| P4 - Low / Info | 24 Hours | 72 Hours | Tier 1 Queue |`
        },
        {
          path: "04-ALERT-LIFECYCLE-AND-TRIAGE/triage-guides/tier1-triage-checklist.md",
          name: "tier1-triage-checklist.md",
          type: "markdown",
          narrative: "Step-by-step verification checklist for Tier 1 analysts handling incoming process execution, network beaconing, and credential access alerts.",
          connections: ["06-THREAT-INTELLIGENCE-AND-IOCS/ioc-manager/domain-blocklist.csv"],
          code: `# Tier 1 Analyst Triage Checklist
1. Validate Alert Fidelity: Verify if event source matches verified asset inventory.
2. Check Observables: Cross-reference IPs, hashes, and domains against Domain 06 IOC blocklists.
3. User Context: Verify if user account is a service account or human operator.
4. Process Lineage: Inspect parent-child relationships for shell spawning.`
        }
      ]
    },
    {
      id: "05",
      name: "05 - Threat Hunting",
      shortName: "Threat Hunting",
      category: "Operations Layer",
      description: "Proactive threat hunting framework based on PEAK methodology: hunt hypotheses, KQL hunt queries, Jupyter notebooks, and reports.",
      files: [
        {
          path: "05-THREAT-HUNTING/hunt-hypotheses/HUNT-2026-01-dll-side-loading.md",
          name: "HUNT-2026-01-dll-side-loading.md",
          type: "markdown",
          narrative: "Formulates hunt hypothesis that adversaries are abusing legitimate signed binaries to side-load unsigned malicious DLLs.",
          connections: ["03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml", "06-THREAT-INTELLIGENCE-AND-IOCS/threat-actor-profiles/APT29-Midnight-Blizzard.md"],
          code: `# Hunt Hypothesis: DLL Side-Loading in Signed Utilities
Hypothesis: Adversaries execute signed Windows binaries from non-standard directories to load malicious DLLs bypassing EDR rules.
Data Sources Needed: Sysmon Event ID 7 (Image Loaded), Sysmon Event ID 1 (Process Create).`
        },
        {
          path: "05-THREAT-HUNTING/hunt-queries/hunting_rare_user_agents.kql",
          name: "hunting_rare_user_agents.kql",
          type: "kql",
          narrative: "Advanced KQL query aggregating proxy telemetry to isolate rare, low-frequency HTTP User-Agents associated with C2 frameworks.",
          connections: ["02-NORMALIZATION-AND-PARSING/field-dictionary.md"],
          code: `CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| summarize Count = count() by RequestHeaderUserAgent, SourceIP
| where Count < 5
| order by Count asc`
        }
      ]
    },
    {
      id: "06",
      name: "06 - Threat Intelligence and IOCs",
      shortName: "Threat Intel",
      category: "Operations Layer",
      description: "CTI repository housing domain/hash/IP blocklists, MITRE ATT&CK coverage heatmaps, and threat actor profiles (APT29).",
      files: [
        {
          path: "06-THREAT-INTELLIGENCE-AND-IOCS/mitre-attack-mapping/coverage-matrix.md",
          name: "coverage-matrix.md",
          type: "markdown",
          narrative: "MITRE ATT&CK detection matrix listing covered techniques (T1003, T1071, T1059) and identifying high-priority detection gaps.",
          connections: ["03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml"],
          code: `# MITRE ATT&CK Detection Coverage Heatmap
| Technique ID | Technique Name | Rule Coverage Count | Verification Status |
| --- | --- | --- | --- |
| T1003.001 | LSASS Memory Dump | 3 Rules (Sigma, KQL) | Validated via Atomic Red Team |
| T1071.004 | DNS C2 Tunneling | 1 Rule (Suricata) | In Progress |
| T1059.001 | PowerShell Execution | 5 Rules | Validated |`
        },
        {
          path: "06-THREAT-INTELLIGENCE-AND-IOCS/threat-actor-profiles/APT29-Midnight-Blizzard.md",
          name: "APT29-Midnight-Blizzard.md",
          type: "markdown",
          narrative: "Profile of APT29 / Midnight Blizzard outlining primary TTPs, OAuth abuse vectors, DLL side-loading, and targeted detection rules.",
          connections: ["05-THREAT-HUNTING/hunt-hypotheses/HUNT-2026-01-dll-side-loading.md"],
          code: `# Threat Actor Profile: APT29 (Midnight Blizzard)
Target Sectors: Government, Defense, Managed Service Providers
Primary TTPs: Token Theft, OAuth App Compromise, DLL Side-Loading
Detection Mapping: kql/privilege-escalation/lsass_memory_dumping.kql`
        }
      ]
    },
    {
      id: "07",
      name: "07 - Incident Response and SOAR",
      shortName: "Incident Response",
      category: "Response Layer",
      description: "Emergency playbooks (Ransomware, Phishing, Credential Dumping), Python SOAR containment scripts, and isolation approval matrices.",
      files: [
        {
          path: "07-INCIDENT-RESPONSE-AND-SOAR/incident-playbooks/credential-dumping-playbook.md",
          name: "credential-dumping-playbook.md",
          type: "markdown",
          narrative: "Actionable IR playbook for confirmed credential dumping incidents: isolation steps, ticket revocation, and memory dump capture.",
          connections: ["07-INCIDENT-RESPONSE-AND-SOAR/soar-automation/python-containment-scripts/isolate_host_edr.py", "08-FORENSICS-AND-ARTEFACTS/memory-forensics/volatility-plugins-and-profiles/volatility3-cheatsheet.md"],
          code: `# Credential Dumping Incident Response Playbook
Step 1: Immediate Host Isolation via EDR API (isolate_host_edr.py).
Step 2: Memory Acquisition prior to host reboot.
Step 3: Force Kerberos Ticket Revocation (krbtgt reset) and user password reset.`
        },
        {
          path: "07-INCIDENT-RESPONSE-AND-SOAR/soar-automation/python-containment-scripts/isolate_host_edr.py",
          name: "isolate_host_edr.py",
          type: "python",
          narrative: "Python SOAR script invoking EDR REST API to network-isolate compromised endpoints while preserving security agent telemetry.",
          connections: ["07-INCIDENT-RESPONSE-AND-SOAR/containment-decisions/isolation-approval-matrix.md"],
          code: `import requests, sys, os

def isolate_endpoint(agent_id, api_token):
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    payload = {"action": "isolate", "target_id": agent_id}
    res = requests.post("https://edr.internal.soc/api/v1/contain", json=payload, headers=headers)
    return res.status_code == 200`
        }
      ]
    },
    {
      id: "08",
      name: "08 - Forensics and Artefacts",
      shortName: "Forensics",
      category: "Response Layer",
      description: "DFIR technical guides covering Windows Event log carving, Volatility 3 memory analysis, E01 disk imaging, PCAPs, and Linux auditd.",
      files: [
        {
          path: "08-FORENSICS-AND-ARTEFACTS/memory-forensics/volatility-plugins-and-profiles/volatility3-cheatsheet.md",
          name: "volatility3-cheatsheet.md",
          type: "markdown",
          narrative: "Volatility 3 cheat sheet for memory dump triage: running windows.pslist, windows.malfind, and windows.netscan.",
          connections: ["09-EVIDENCE-MANAGEMENT/evidence-hashing-logs/evidence-verification-log.md"],
          code: `# Volatility 3 Memory Forensics Command Reference
1. List Active Processes: vol -f memdump.raw windows.pslist
2. Detect Injected Code: vol -f memdump.raw windows.malfind
3. Scan Network Connections: vol -f memdump.raw windows.netscan`
        }
      ]
    },
    {
      id: "09",
      name: "09 - Evidence Management",
      shortName: "Evidence Locker",
      category: "Governance Layer",
      description: "Legal chain of custody logging, SHA-256 evidence hashing logs, and secure vault storage security standards.",
      files: [
        {
          path: "09-EVIDENCE-MANAGEMENT/chain-of-custody/custody-log-template.md",
          name: "custody-log-template.md",
          type: "markdown",
          narrative: "Official chain of custody log template recording evidence transfers, custodian signatures, and hash verification logs.",
          connections: ["11-GRC-AUDIT-AND-COMPLIANCE/compliance-frameworks/soc2-type2-mapping.md"],
          code: `# Legal Chain of Custody Log
Item Reference: INC-2026-089-EV1
Evidence Description: Physical E01 Disk Image of Host WS-908
SHA-256 Hash: 0bf5ee2bb8beb0814f17f1d76249565937ea6263242193848fac6c6eb69f6049
Custodian: DFIR Specialist Lead`
        }
      ]
    },
    {
      id: "10",
      name: "10 - Metrics, KPIs, and Reporting",
      shortName: "Metrics & KPIs",
      category: "Governance Layer",
      description: "SOC performance metrics (MTTD, MTTR), monthly CISO executive reports, and Post-Incident Reviews (PIR / RCA).",
      files: [
        {
          path: "10-METRICS-KPI-AND-REPORTING/soc-kpis/mttd-mttr-dashboard-spec.md",
          name: "mttd-mttr-dashboard-spec.md",
          type: "markdown",
          narrative: "Specification for MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond) operational performance dashboards.",
          connections: ["04-ALERT-LIFECYCLE-AND-TRIAGE/severity-matrix-and-sla/sla-definitions.md"],
          code: `# MTTD & MTTR KPI Specification
Target MTTD (Mean Time to Detect): < 15 Minutes across P1/P2 alerts
Target MTTR (Mean Time to Respond): < 45 Minutes for containment
Data Calculation: Time(Alert Fired) - Time(Host Isolated)`
        }
      ]
    },
    {
      id: "11",
      name: "11 - GRC, Audit, and Compliance",
      shortName: "GRC & Compliance",
      category: "Governance Layer",
      description: "Audit evidence mapping linking technical telemetry to SOC 2 Type II, ISO 27001:2022, NIST CSF 2.0, and Risk Registers.",
      files: [
        {
          path: "11-GRC-AUDIT-AND-COMPLIANCE/compliance-frameworks/soc2-type2-mapping.md",
          name: "soc2-type2-mapping.md",
          type: "markdown",
          narrative: "Direct mapping of technical logs, detection rules, and evidence logs to SOC 2 Type II Trust Services Criteria.",
          connections: ["01-DATA-SOURCES-AND-INGESTION/log-retention-and-dlp/log-retention-policy.md", "09-EVIDENCE-MANAGEMENT/chain-of-custody/custody-log-template.md"],
          code: `# SOC 2 Type II Evidence Mapping Matrix
| Trust Criteria | Requirement Description | Operational Evidence Source File |
| --- | --- | --- |
| CC6.1 | Logical Access Controls | 11-GRC-AUDIT-AND-COMPLIANCE/audit-evidence-locker/access-review-evidence/quarterly-pam-access-review.md |
| CC6.8 | Malicious Code Detection | 03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml |
| CC7.2 | Security Incident Monitoring | 04-ALERT-LIFECYCLE-AND-TRIAGE/severity-matrix-and-sla/sla-definitions.md |`
        }
      ]
    }
  ],

  mitreHeatmap: [
    { id: "T1003.001", name: "LSASS Memory Dumping", count: 3, category: "Credential Access", rules: ["proc_creation_win_mimikatz_cmdline.yml", "lsass_memory_dumping.kql"] },
    { id: "T1071.004", name: "DNS C2 Tunneling", count: 2, category: "Command & Control", rules: ["emerging_threats_c2.rules", "hunting_rare_user_agents.kql"] },
    { id: "T1059.001", name: "PowerShell Execution", count: 4, category: "Execution", rules: ["suspicious_cmd_parent_child.kql"] },
    { id: "T1547.001", name: "Registry Run Keys", count: 2, category: "Persistence", rules: ["registry_runkeys_modification.kql"] },
    { id: "T1027", name: "Obfuscated Files/Scripts", count: 3, category: "Defense Evasion", rules: ["php_webshell_obfuscated.yar"] }
  ],

  sampleLogs: [
    { recId: 1, eventId: 4688, source: "Security Auditing", time: "2021-12-07 17:33:01", process: "MalSeclogon.exe", detail: "CommandLine: MalSeclogon.exe -p 636 -d 2" },
    { recId: 2, eventId: 1, source: "Sysmon", time: "2021-12-07 17:33:01", process: "MalSeclogon.exe", detail: "ParentImage: cmd.exe | SHA256: 0BF5EE2BB8BEB0814F17F..." },
    { recId: 3, eventId: 4703, source: "Security Auditing", time: "2021-12-07 17:33:01", process: "MalSeclogon.exe", detail: "EnabledPrivilegeList: SeDebugPrivilege" },
    { recId: 10, eventId: 10, source: "Sysmon", time: "2021-12-07 17:33:01", process: "MalSeclogon.exe", detail: "TargetImage: lsass.exe | GrantedAccess: 0x00100000" },
    { recId: 13, eventId: 10, source: "Sysmon", time: "2021-12-07 17:33:01", process: "MalSeclogon.exe", detail: "TargetImage: lsass.exe | GrantedAccess: 0x00001410" }
  ]
};

// UI State
let currentDomainId = "01";
let currentFileIdx = 0;

document.addEventListener("DOMContentLoaded", () => {
  renderSidebar();
  renderDomainOverview("01");
  renderWorkspace("01", 0);
  setupTabListeners();
  setupSearch();
});

function renderSidebar() {
  const domainListEl = document.getElementById("domainList");
  if (!domainListEl) return;

  domainListEl.innerHTML = ECOSYSTEM_DATA.domains.map(domain => `
    <li class="domain-item ${domain.id === currentDomainId ? 'active' : ''}" onclick="selectDomain('${domain.id}')">
      <div class="domain-item-header">
        <span class="domain-number">${domain.id}</span>
        <span class="domain-title">${domain.shortName}</span>
        <span class="file-count">${domain.files.length} files</span>
      </div>
    </li>
  `).join("");
}

function selectDomain(domainId) {
  currentDomainId = domainId;
  currentFileIdx = 0;
  renderSidebar();
  renderDomainOverview(domainId);
  renderWorkspace(domainId, 0);
}

function renderDomainOverview(domainId) {
  const domain = ECOSYSTEM_DATA.domains.find(d => d.id === domainId);
  if (!domain) return;

  const overviewEl = document.getElementById("domainOverview");
  if (!overviewEl) return;

  overviewEl.innerHTML = `
    <div class="domain-badge-bar">
      <span class="tag-badge">${domain.category}</span>
      <span class="tag-badge">Domain ${domain.id}</span>
    </div>
    <h2 class="domain-overview-title">${domain.name}</h2>
    <p class="domain-overview-desc">${domain.description}</p>
  `;
}

function renderWorkspace(domainId, fileIdx) {
  const domain = ECOSYSTEM_DATA.domains.find(d => d.id === domainId);
  if (!domain || !domain.files[fileIdx]) return;

  currentFileIdx = fileIdx;
  const currentFile = domain.files[fileIdx];

  // Render File List
  const fileListEl = document.getElementById("fileList");
  if (fileListEl) {
    fileListEl.innerHTML = domain.files.map((file, idx) => `
      <li class="file-node ${idx === fileIdx ? 'active' : ''}" onclick="selectFile(${idx})">
        ${file.name}
      </li>
    `).join("");
  }

  // Render Code Inspector
  const codeInspectorEl = document.getElementById("codeInspector");
  if (codeInspectorEl) {
    const lines = currentFile.code.split('\n');
    const formattedCode = lines.map((line, i) => `
      <div class="code-line">
        <span class="line-num">${i + 1}</span>
        <span class="line-text">${escapeHtml(line)}</span>
      </div>
    `).join("");

    codeInspectorEl.innerHTML = `
      <div class="code-meta-bar">
        <span class="code-path">${currentFile.path}</span>
        <span class="tag-badge">${currentFile.type.toUpperCase()}</span>
      </div>
      <div class="code-container">
        ${formattedCode}
      </div>
    `;
  }

  // Render AI Narrator
  const narratorEl = document.getElementById("narratorContent");
  if (narratorEl) {
    narratorEl.innerHTML = `
      <div class="narrator-box">
        <div class="narrator-title">Operational Function</div>
        <p class="narrator-content">${currentFile.narrative}</p>
      </div>
      <div class="narrator-box">
        <div class="narrator-title">Connected Workflows & Dependents</div>
        <div class="connection-pill-list">
          ${currentFile.connections.map(conn => `
            <div class="connection-pill">
              <span>${conn}</span>
              <span class="connection-direction">LINKED</span>
            </div>
          `).join("")}
        </div>
      </div>
    `;
  }
}

function selectFile(fileIdx) {
  renderWorkspace(currentDomainId, fileIdx);
}

function setupTabListeners() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const viewMode = tab.dataset.view;
      switchViewMode(viewMode);
    });
  });
}

function switchViewMode(mode) {
  const workspaceView = document.getElementById("workspaceView");
  const flowGraphView = document.getElementById("flowGraphView");
  const mitreView = document.getElementById("mitreView");
  const logExplorerView = document.getElementById("logExplorerView");

  [workspaceView, flowGraphView, mitreView, logExplorerView].forEach(v => {
    if (v) v.style.display = "none";
  });

  if (mode === "workspace" && workspaceView) workspaceView.style.display = "grid";
  if (mode === "flow" && flowGraphView) {
    flowGraphView.style.display = "block";
    renderFlowGraph();
  }
  if (mode === "mitre" && mitreView) {
    mitreView.style.display = "block";
    renderMitreHeatmap();
  }
  if (mode === "logs" && logExplorerView) {
    logExplorerView.style.display = "block";
    renderLogExplorer();
  }
}

function renderFlowGraph() {
  const container = document.getElementById("flowGraphContent");
  if (!container) return;

  container.innerHTML = ECOSYSTEM_DATA.domains.map((dom, i) => `
    <div class="flow-step-card">
      <div class="flow-step-num">${dom.id}</div>
      <div class="flow-step-domain">${dom.shortName}</div>
      <div class="flow-step-desc">${dom.description}</div>
      <div class="flow-step-files">${dom.files.length} active assets</div>
    </div>
  `).join("");
}

function renderMitreHeatmap() {
  const container = document.getElementById("mitreGridContent");
  if (!container) return;

  container.innerHTML = ECOSYSTEM_DATA.mitreHeatmap.map(item => `
    <div class="mitre-card">
      <span class="mitre-id">${item.id}</span>
      <div class="mitre-name">${item.name}</div>
      <div class="mitre-rules-count">${item.category} • ${item.count} Rules</div>
    </div>
  `).join("");
}

function renderLogExplorer() {
  const container = document.getElementById("logExplorerContent");
  if (!container) return;

  container.innerHTML = `
    <table class="log-explorer-table">
      <thead>
        <tr>
          <th>Rec #</th>
          <th>Event ID</th>
          <th>Provider</th>
          <th>Timestamp</th>
          <th>Process</th>
          <th>Log Details</th>
        </tr>
      </thead>
      <tbody>
        ${ECOSYSTEM_DATA.sampleLogs.map(log => `
          <tr>
            <td>${log.recId}</td>
            <td><strong>${log.eventId}</strong></td>
            <td>${log.source}</td>
            <td>${log.time}</td>
            <td>${log.process}</td>
            <td>${escapeHtml(log.detail)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function setupSearch() {
  const searchInput = document.getElementById("searchInput");
  if (!searchInput) return;

  searchInput.addEventListener("input", (e) => {
    const query = e.target.value.toLowerCase();
    if (!query) {
      renderSidebar();
      return;
    }

    const filtered = ECOSYSTEM_DATA.domains.filter(d => 
      d.name.toLowerCase().includes(query) || 
      d.description.toLowerCase().includes(query) ||
      d.files.some(f => f.name.toLowerCase().includes(query) || f.path.toLowerCase().includes(query))
    );

    const domainListEl = document.getElementById("domainList");
    if (domainListEl) {
      domainListEl.innerHTML = filtered.map(domain => `
        <li class="domain-item ${domain.id === currentDomainId ? 'active' : ''}" onclick="selectDomain('${domain.id}')">
          <div class="domain-item-header">
            <span class="domain-number">${domain.id}</span>
            <span class="domain-title">${domain.shortName}</span>
          </div>
        </li>
      `).join("");
    }
  });
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
