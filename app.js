/* ===============================================================================
   SOC & GRC ECOSYSTEM - ARCHITECTURE DATA & ENGINE
   PURE TECHNICAL DATA STORE & VISUALIZER ENGINE
   =============================================================================== */

const REPO_DATA = {
  domains: [
    {
      id: "01",
      name: "01 - Data Sources and Ingestion",
      shortName: "Data Ingestion",
      description: "Log source inventories, Sysmon endpoint configuration, and log forwarding topologies.",
      files: [
        {
          path: "01-DATA-SOURCES-AND-INGESTION/README.md",
          name: "README.md",
          purpose: "Master pipeline architecture reference for log ingestion topology.",
          links: ["02-NORMALIZATION-AND-PARSING/README.md", "03-DETECTION-ENGINEERING/README.md"],
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
          purpose: "Fluent Bit configuration streaming endpoint syslog data to Elasticsearch pipelines.",
          links: ["02-NORMALIZATION-AND-PARSING/field-dictionary.md"],
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
          purpose: "Winlogbeat configuration for replaying EVTX attack sample logs into elasticsearch.",
          links: ["03-DETECTION-ENGINEERING/test-data/windows-evtx/"],
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
          purpose: "Production Sysmon XML configuration filtering Event IDs 1, 3, 7, and 10.",
          links: ["03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml"],
          code: `<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">cmd.exe</CommandLine>
      <CommandLine condition="contains">powershell.exe</CommandLine>
    </ProcessCreate>
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
      description: "Canonical field dictionary and Grok parsers mapping vendor logs to ECS & OCSF.",
      files: [
        {
          path: "02-NORMALIZATION-AND-PARSING/field-dictionary.md",
          name: "field-dictionary.md",
          purpose: "Canonical naming standard mapping vendor raw fields (Sysmon, Windows) to unified SOC terms.",
          links: ["03-DETECTION-ENGINEERING/kql/process-execution/suspicious_cmd_parent_child.kql"],
          code: `# Enterprise Field Dictionary Taxonomy
| Vendor Source Field | Unified SOC Field Term | ECS Mapping | OCSF Mapping |
| --- | --- | --- | --- |
| Sysmon Image | process.executable | process.name | process.file.name |
| Sysmon ParentImage | process.parent.executable | process.parent.name | process.parent_process.name |
| EventID 4688 NewProcessName | process.name | process.executable | process.name |`
        },
        {
          path: "02-NORMALIZATION-AND-PARSING/custom-parsers/syslog-parsers/palo-alto-firewall.grok",
          name: "palo-alto-firewall.grok",
          purpose: "Logstash Grok pattern extracting Palo Alto firewall syslog fields into named tokens.",
          links: ["03-DETECTION-ENGINEERING/suricata-snort/network-signatures/emerging_threats_c2.rules"],
          code: `PALOALTO_TRAFFIC %{TIMESTAMP_ISO8601:log_time},%{WORD:serial_number},%{WORD:type},%{WORD:subtype},%{IP:source_ip},%{IP:destination_ip},%{INT:source_port},%{INT:destination_port}`
        }
      ]
    },
    {
      id: "03",
      name: "03 - Detection Engineering",
      shortName: "Detection Engineering",
      description: "Detection-as-Code repository: Sigma YAML rules, KQL queries, YARA rules, and Atomic Red Team tests.",
      files: [
        {
          path: "03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml",
          name: "proc_creation_win_mimikatz_cmdline.yml",
          purpose: "Sigma detection rule for Mimikatz command-line credential dumping arguments.",
          links: ["04-ALERT-LIFECYCLE-AND-TRIAGE/triage-guides/tier1-triage-checklist.md", "06-THREAT-INTELLIGENCE-AND-IOCS/mitre-attack-mapping/coverage-matrix.md"],
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
          purpose: "Microsoft Sentinel KQL query targeting LSASS memory reading (GrantedAccess 0x1410).",
          links: [".github/workflows/kql-lint-check.yml", "07-INCIDENT-RESPONSE-AND-SOAR/incident-playbooks/credential-dumping-playbook.md"],
          code: `Sysmon
| where EventID == 10
| where TargetImage endswith "lsass.exe"
| where GrantedAccess in ("0x1000", "0x1410", "0x1F0FFF")
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, SourceProcessId`
        },
        {
          path: "03-DETECTION-ENGINEERING/detection-testing/atomic-red-team-tests/T1003.001-lsass-dump-test.yaml",
          name: "T1003.001-lsass-dump-test.yaml",
          purpose: "Atomic Red Team test YAML executing LSASS minidump via comsvcs.dll.",
          links: ["03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml"],
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
      description: "Severity SLAs (P1-P4), Tier 1-3 analyst SOP checklists, and shift handover protocols.",
      files: [
        {
          path: "04-ALERT-LIFECYCLE-AND-TRIAGE/severity-matrix-and-sla/sla-definitions.md",
          name: "sla-definitions.md",
          purpose: "SLA resolution targets and escalation boundaries for incident response.",
          links: ["10-METRICS-KPI-AND-REPORTING/soc-kpis/mttd-mttr-dashboard-spec.md"],
          code: `# Incident Severity Matrix & SLA Resolution Targets
| Severity Level | Response SLA | Containment SLA | Escalation Target |
| --- | --- | --- | --- |
| P1 - Critical | 15 Minutes | 1 Hour | Tier 3 Lead & CISO |
| P2 - High | 30 Minutes | 4 Hours | Tier 2 IR Lead |
| P3 - Medium | 2 Hours | 24 Hours | Tier 1 Analyst |`
        },
        {
          path: "04-ALERT-LIFECYCLE-AND-TRIAGE/triage-guides/tier1-triage-checklist.md",
          name: "tier1-triage-checklist.md",
          purpose: "Operational checklist for validating process execution and IOC alerts.",
          links: ["06-THREAT-INTELLIGENCE-AND-IOCS/ioc-manager/domain-blocklist.csv"],
          code: `# Tier 1 Analyst Triage Checklist
1. Validate Alert Fidelity: Verify if event source matches verified asset inventory.
2. Check Observables: Cross-reference IPs, hashes, and domains against Domain 06 IOC blocklists.
3. User Context: Verify if user account is a service account or human operator.`
        }
      ]
    },
    {
      id: "05",
      name: "05 - Threat Hunting",
      shortName: "Threat Hunting",
      description: "PEAK methodology hunt hypotheses, KQL hunt queries, and Jupyter notebook analysis.",
      files: [
        {
          path: "05-THREAT-HUNTING/hunt-hypotheses/HUNT-2026-01-dll-side-loading.md",
          name: "HUNT-2026-01-dll-side-loading.md",
          purpose: "Hunt hypothesis investigating DLL side-loading in signed Windows binaries.",
          links: ["06-THREAT-INTELLIGENCE-AND-IOCS/threat-actor-profiles/APT29-Midnight-Blizzard.md"],
          code: `# Hunt Hypothesis: DLL Side-Loading in Signed Utilities
Hypothesis: Adversaries execute signed Windows binaries from non-standard directories to load malicious DLLs bypassing EDR rules.
Data Sources Needed: Sysmon Event ID 7 (Image Loaded), Sysmon Event ID 1 (Process Create).`
        }
      ]
    },
    {
      id: "06",
      name: "06 - Threat Intelligence and IOCs",
      shortName: "Threat Intel",
      description: "IOC blocklists, MITRE ATT&CK coverage heatmap, and threat actor profiles.",
      files: [
        {
          path: "06-THREAT-INTELLIGENCE-AND-IOCS/mitre-attack-mapping/coverage-matrix.md",
          name: "coverage-matrix.md",
          purpose: "Heatmap mapping active detection rules to MITRE ATT&CK techniques.",
          links: ["03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml"],
          code: `# MITRE ATT&CK Detection Coverage Heatmap
| Technique ID | Technique Name | Rule Coverage Count | Verification Status |
| --- | --- | --- | --- |
| T1003.001 | LSASS Memory Dump | 3 Rules (Sigma, KQL) | Validated via Atomic Red Team |
| T1071.004 | DNS C2 Tunneling | 1 Rule (Suricata) | In Progress |`
        }
      ]
    },
    {
      id: "07",
      name: "07 - Incident Response and SOAR",
      shortName: "Incident Response",
      description: "Emergency playbooks (Credential Dumping, Ransomware) and Python containment scripts.",
      files: [
        {
          path: "07-INCIDENT-RESPONSE-AND-SOAR/soar-automation/python-containment-scripts/isolate_host_edr.py",
          name: "isolate_host_edr.py",
          purpose: "Python script calling EDR REST API to network-isolate compromised host.",
          links: ["07-INCIDENT-RESPONSE-AND-SOAR/containment-decisions/isolation-approval-matrix.md"],
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
      description: "Technical DFIR cheat sheets for Volatility 3, EVTX carving, and network PCAPs.",
      files: [
        {
          path: "08-FORENSICS-AND-ARTEFACTS/memory-forensics/volatility-plugins-and-profiles/volatility3-cheatsheet.md",
          name: "volatility3-cheatsheet.md",
          purpose: "Volatility 3 command reference for memory forensics triage.",
          links: ["09-EVIDENCE-MANAGEMENT/evidence-hashing-logs/evidence-verification-log.md"],
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
      description: "Legal chain of custody logging and SHA-256 evidence integrity logs.",
      files: [
        {
          path: "09-EVIDENCE-MANAGEMENT/chain-of-custody/custody-log-template.md",
          name: "custody-log-template.md",
          purpose: "Legal chain of custody template for forensic artefacts.",
          links: ["11-GRC-AUDIT-AND-COMPLIANCE/compliance-frameworks/soc2-type2-mapping.md"],
          code: `# Legal Chain of Custody Log
Item Reference: INC-2026-089-EV1
Evidence Description: Physical E01 Disk Image of Host WS-908
SHA-256 Hash: 0bf5ee2bb8beb0814f17f1d76249565937ea6263242193848fac6c6eb69f6049`
        }
      ]
    },
    {
      id: "10",
      name: "10 - Metrics, KPIs, and Reporting",
      shortName: "Metrics & KPIs",
      description: "MTTD and MTTR performance dashboard specifications and CISO reports.",
      files: [
        {
          path: "10-METRICS-KPI-AND-REPORTING/soc-kpis/mttd-mttr-dashboard-spec.md",
          name: "mttd-mttr-dashboard-spec.md",
          purpose: "KPI calculation specification for MTTD and MTTR response times.",
          links: ["04-ALERT-LIFECYCLE-AND-TRIAGE/severity-matrix-and-sla/sla-definitions.md"],
          code: `# MTTD & MTTR KPI Specification
Target MTTD (Mean Time to Detect): < 15 Minutes across P1/P2 alerts
Target MTTR (Mean Time to Respond): < 45 Minutes for containment`
        }
      ]
    },
    {
      id: "11",
      name: "11 - GRC, Audit, and Compliance",
      shortName: "GRC & Compliance",
      description: "Compliance evidence mapping linking telemetry to SOC 2 Type II, ISO 27001, and NIST CSF 2.0.",
      files: [
        {
          path: "11-GRC-AUDIT-AND-COMPLIANCE/compliance-frameworks/soc2-type2-mapping.md",
          name: "soc2-type2-mapping.md",
          purpose: "SOC 2 Type II control evidence mapping matrix.",
          links: ["01-DATA-SOURCES-AND-INGESTION/log-retention-and-dlp/log-retention-policy.md"],
          code: `# SOC 2 Type II Evidence Mapping Matrix
| Trust Criteria | Requirement Description | Operational Evidence Source File |
| --- | --- | --- |
| CC6.1 | Logical Access Controls | 11-GRC-AUDIT-AND-COMPLIANCE/audit-evidence-locker/access-review-evidence/quarterly-pam-access-review.md |
| CC6.8 | Malicious Code Detection | 03-DETECTION-ENGINEERING/sigma/windows/proc_creation_win_mimikatz_cmdline.yml |`
        }
      ]
    }
  ],

  mitreTable: [
    { id: "T1003.001", name: "LSASS Memory Dumping", tactic: "Credential Access", rules: "proc_creation_win_mimikatz_cmdline.yml, lsass_memory_dumping.kql" },
    { id: "T1071.004", name: "DNS C2 Tunneling", tactic: "Command & Control", rules: "emerging_threats_c2.rules, hunting_rare_user_agents.kql" },
    { id: "T1059.001", name: "PowerShell Execution", tactic: "Execution", rules: "suspicious_cmd_parent_child.kql" },
    { id: "T1547.001", name: "Registry Run Keys", tactic: "Persistence", rules: "registry_runkeys_modification.kql" }
  ],

  logRecords: [
    { id: 1, eid: 4688, source: "Security Auditing", time: "2021-12-07 17:33:01", info: "Process: MalSeclogon.exe | Parent: cmd.exe | User: IEUser" },
    { id: 2, eid: 1, source: "Sysmon", time: "2021-12-07 17:33:01", info: "Image: MalSeclogon.exe | CmdLine: MalSeclogon.exe -p 636 -d 2" },
    { id: 3, eid: 4703, source: "Security Auditing", time: "2021-12-07 17:33:01", info: "Privilege: SeDebugPrivilege Enabled" },
    { id: 10, eid: 10, source: "Sysmon", time: "2021-12-07 17:33:01", info: "Target: lsass.exe | GrantedAccess: 0x00100000" },
    { id: 13, eid: 10, source: "Sysmon", time: "2021-12-07 17:33:01", info: "Target: lsass.exe | GrantedAccess: 0x00001410 (Read Memory)" }
  ]
};

let activeDomainId = "01";
let activeFileIdx = 0;

document.addEventListener("DOMContentLoaded", () => {
  renderSidebar();
  renderDomain(activeDomainId, 0);
  bindNavButtons();
  bindThemeButtons();
});

function renderSidebar() {
  const el = document.getElementById("domainNav");
  if (!el) return;

  el.innerHTML = REPO_DATA.domains.map(d => `
    <li class="domain-nav-item ${d.id === activeDomainId ? 'active' : ''}" onclick="selectDomain('${d.id}')">
      <span class="domain-id">${d.id}</span>
      <span>${d.shortName}</span>
    </li>
  `).join("");
}

function selectDomain(domainId) {
  activeDomainId = domainId;
  activeFileIdx = 0;
  renderSidebar();
  renderDomain(domainId, 0);
}

function renderDomain(domainId, fileIdx) {
  const domain = REPO_DATA.domains.find(d => d.id === domainId);
  if (!domain || !domain.files[fileIdx]) return;

  activeFileIdx = fileIdx;
  const file = domain.files[fileIdx];

  // Header
  const headerEl = document.getElementById("domainHeader");
  if (headerEl) {
    headerEl.innerHTML = `
      <h2>${domain.name}</h2>
      <p>${domain.description}</p>
    `;
  }

  // Asset List
  const assetListEl = document.getElementById("assetList");
  if (assetListEl) {
    assetListEl.innerHTML = domain.files.map((f, i) => `
      <li class="asset-item ${i === fileIdx ? 'active' : ''}" onclick="selectFile(${i})">
        ${f.name}
      </li>
    `).join("");
  }

  // Code Viewer
  const codeViewerEl = document.getElementById("codeViewer");
  if (codeViewerEl) {
    const lines = file.code.split('\n');
    const formatted = lines.map((l, idx) => `
      <div class="code-line">
        <span class="line-no">${idx + 1}</span>
        <span class="line-val">${escape(l)}</span>
      </div>
    `).join("");

    codeViewerEl.innerHTML = `
      <div style="font-family: 'Fira Code', monospace; font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 0.5rem;">
        ${file.path}
      </div>
      <div class="code-box">${formatted}</div>
    `;
  }

  // Context Viewer
  const contextEl = document.getElementById("contextViewer");
  if (contextEl) {
    contextEl.innerHTML = `
      <div class="context-box">
        <div class="context-label">Purpose</div>
        <div class="context-text">${file.purpose}</div>
      </div>
      <div class="context-box">
        <div class="context-label">Linked Files & Dependencies</div>
        <div class="link-list">
          ${file.links.map(l => `<div class="link-item">${l}</div>`).join("")}
        </div>
      </div>
    `;
  }
}

function selectFile(idx) {
  renderDomain(activeDomainId, idx);
}

function bindNavButtons() {
  const btns = document.querySelectorAll(".nav-btn");
  btns.forEach(btn => {
    btn.addEventListener("click", () => {
      btns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      showView(btn.dataset.view);
    });
  });
}

function bindThemeButtons() {
  const btns = document.querySelectorAll(".theme-btn");
  btns.forEach(btn => {
    btn.addEventListener("click", () => {
      btns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const theme = btn.dataset.theme;
      document.documentElement.setAttribute("data-theme", theme);
    });
  });
}

function showView(view) {
  const ws = document.getElementById("workspaceView");
  const flow = document.getElementById("flowView");
  const mitre = document.getElementById("mitreView");
  const log = document.getElementById("logView");

  [ws, flow, mitre, log].forEach(v => { if (v) v.style.display = "none"; });

  if (view === "workspace" && ws) ws.style.display = "grid";
  if (view === "flow" && flow) {
    flow.style.display = "block";
    renderFlow();
  }
  if (view === "mitre" && mitre) {
    mitre.style.display = "block";
    renderMitre();
  }
  if (view === "logs" && log) {
    log.style.display = "block";
    renderLogs();
  }
}

function renderFlow() {
  const el = document.getElementById("flowContent");
  if (!el) return;

  el.innerHTML = REPO_DATA.domains.map(d => `
    <div class="flow-step">
      <div class="flow-step-id">${d.id}</div>
      <div class="flow-step-name">${d.shortName}</div>
      <div class="flow-step-text">${d.description}</div>
    </div>
  `).join("");
}

function renderMitre() {
  const el = document.getElementById("mitreContent");
  if (!el) return;

  el.innerHTML = `
    <table class="table">
      <thead>
        <tr>
          <th>Technique ID</th>
          <th>Technique Name</th>
          <th>Tactic</th>
          <th>Associated Rule / Detection</th>
        </tr>
      </thead>
      <tbody>
        ${REPO_DATA.mitreTable.map(m => `
          <tr>
            <td><strong>${m.id}</strong></td>
            <td>${m.name}</td>
            <td>${m.tactic}</td>
            <td>${m.rules}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderLogs() {
  const el = document.getElementById("logContent");
  if (!el) return;

  el.innerHTML = `
    <table class="table">
      <thead>
        <tr>
          <th>Rec #</th>
          <th>Event ID</th>
          <th>Provider</th>
          <th>Timestamp</th>
          <th>Event Summary & Parsed Attributes</th>
        </tr>
      </thead>
      <tbody>
        ${REPO_DATA.logRecords.map(r => `
          <tr>
            <td>${r.id}</td>
            <td><strong>${r.eid}</strong></td>
            <td>${r.source}</td>
            <td>${r.time}</td>
            <td>${r.info}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function escape(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
