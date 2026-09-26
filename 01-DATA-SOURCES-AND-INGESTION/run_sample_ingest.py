#!/usr/bin/env python3
"""
===============================================================================
FILE PATH: 01-DATA-SOURCES-AND-INGESTION/run_sample_ingest.py
PURPOSE: Daily Operational Log Parser, Normalizer, and Detection Engine.
         Parses raw Windows EVTX binary logs, converts XML nodes to normalized
         JSON, and tests detection rules against event telemetry.
===============================================================================
"""

import os
import sys
import json
import xml.etree.ElementTree as ET
import Evtx.Evtx as evtx

# Path constants
DEFAULT_EVTX = os.path.join(
    os.path.dirname(__file__),
    "sample-logs/windows/evtx-attack-samples/Execution/revshell_cmd_svchost_sysmon_1.evtx"
)
OUTPUT_JSON = os.path.join(
    os.path.dirname(__file__),
    "../02-NORMALIZATION-AND-PARSING/sample-normalized-events.json"
)

def strip_namespace(tag):
    """Remove XML namespace prefix if present."""
    return tag.split('}')[-1] if '}' in tag else tag

def parse_evtx_record(xml_str):
    """
    Parses XML record from EVTX and extracts key telemetry fields:
    EventID, System Time, Computer, Provider, Data/EventData key-values.
    """
    try:
        root = ET.fromstring(xml_str)
    except Exception as e:
        return None

    event_data = {}
    system_data = {}

    for elem in root:
        tag_name = strip_namespace(elem.tag)
        if tag_name == "System":
            for child in elem:
                c_tag = strip_namespace(child.tag)
                if c_tag == "EventID":
                    system_data["EventID"] = child.text
                elif c_tag == "TimeCreated":
                    system_data["SystemTime"] = child.attrib.get("SystemTime", "")
                elif c_tag == "Computer":
                    system_data["Computer"] = child.text
                elif c_tag == "Provider":
                    system_data["Provider"] = child.attrib.get("Name", "")
                elif c_tag == "Execution":
                    system_data["ProcessID"] = child.attrib.get("ProcessID", "")
                    system_data["ThreadID"] = child.attrib.get("ThreadID", "")

        elif tag_name in ("EventData", "UserData"):
            for child in elem:
                c_tag = strip_namespace(child.tag)
                if c_tag == "Data":
                    name = child.attrib.get("Name", "")
                    value = child.text or ""
                    if name:
                        event_data[name] = value
                else:
                    # General elements under UserData/EventData
                    if child.text:
                        event_data[c_tag] = child.text

    normalized = {
        "event_id": system_data.get("EventID", "Unknown"),
        "timestamp": system_data.get("SystemTime", ""),
        "computer": system_data.get("Computer", ""),
        "provider": system_data.get("Provider", ""),
        "image": event_data.get("Image", event_data.get("NewProcessName", "")),
        "command_line": event_data.get("CommandLine", ""),
        "parent_image": event_data.get("ParentImage", event_data.get("ParentProcessName", "")),
        "parent_command_line": event_data.get("ParentCommandLine", ""),
        "user": event_data.get("User", event_data.get("SubjectUserName", "")),
        "hashes": event_data.get("Hashes", ""),
        "process_id": event_data.get("ProcessId", system_data.get("ProcessID", "")),
        "raw_event_data": event_data
    }
    return normalized

def run_sample_ingest(evtx_path):
    print("=" * 80)
    print(f"[*] SOC DAILY LAB - DOMAIN 01 & 02 INGESTION & NORMALIZATION")
    print(f"[*] Target EVTX File: {evtx_path}")
    print("=" * 80)

    if not os.path.exists(evtx_path):
        print(f"[!] Error: File not found: {evtx_path}")
        return

    events = []
    count = 0

    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            count += 1
            xml_content = record.xml()
            parsed_event = parse_evtx_record(xml_content)
            if parsed_event:
                events.append(parsed_event)

    print(f"[+] Ingested {count} raw events from EVTX log.")
    print(f"[+] Successfully normalized {len(events)} event records.\n")

    # Display preview of normalized event(s)
    print("-" * 80)
    print("[*] NORMALIZED EVENT PREVIEW (Top 3 Records):")
    print("-" * 80)

    for i, event in enumerate(events[:3], start=1):
        print(f"\n--- [RECORD {i}] ---")
        print(f"  Event ID     : {event['event_id']}")
        print(f"  Timestamp    : {event['timestamp']}")
        print(f"  Computer     : {event['computer']}")
        print(f"  User         : {event['user']}")
        print(f"  Image        : {event['image']}")
        print(f"  CommandLine  : {event['command_line']}")
        print(f"  ParentImage  : {event['parent_image']}")

    # Save output to Domain 02
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print("\n" + "=" * 80)
    print(f"[+] SAVED NORMALIZED JSON -> {OUTPUT_JSON}")
    print("=" * 80)

    # Simple Detection Matching Engine Demonstration (Domain 03 Preview)
    print("\n" + "=" * 80)
    print("[*] DOMAIN 03 - DETECTION MATCHING TEST")
    print("=" * 80)

    alerts = []
    for event in events:
        cmd = event.get("command_line", "").lower()
        img = event.get("image", "").lower()
        parent_img = event.get("parent_image", "").lower()

        # Rule 1: Suspicious cmd.exe spawned by svchost.exe (Reverse Shell Indicator)
        if "svchost.exe" in parent_img and "cmd.exe" in img:
            alerts.append({
                "rule_name": "Suspicious Cmd Executed by Svchost",
                "severity": "CRITICAL",
                "mitre_id": "T1059.003 - Command and Scripting Interpreter: Windows Command Shell",
                "matched_event": event
            })
        
        # Rule 2: Encoded or Bypass PowerShell Execution
        elif "powershell" in img and ("-enc" in cmd or "-bypass" in cmd or "-nop" in cmd):
            alerts.append({
                "rule_name": "Suspicious Encoded/Bypass PowerShell Execution",
                "severity": "HIGH",
                "mitre_id": "T1059.001 - Command and Scripting Interpreter: PowerShell",
                "matched_event": event
            })

    if alerts:
        print(f"[!] DETECTED {len(alerts)} THREAT ALERT(S):")
        for alert in alerts:
            print(f"\n  [ALERT TRIGGERED] : {alert['rule_name']}")
            print(f"  [SEVERITY]       : {alert['severity']}")
            print(f"  [MITRE ATT&CK]   : {alert['mitre_id']}")
            print(f"  [PROCESS]        : {alert['matched_event']['image']}")
            print(f"  [COMMAND LINE]   : {alert['matched_event']['command_line']}")
            print(f"  [PARENT PROCESS] : {alert['matched_event']['parent_image']}")
    else:
        print("[+] No alerts triggered based on default test rules.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EVTX
    run_sample_ingest(target)
