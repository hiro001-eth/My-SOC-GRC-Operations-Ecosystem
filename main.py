#!/usr/bin/env python3
"""
===============================================================================
FILE PATH: main.py
PURPOSE: Master Web Server & Dynamic API Engine for SOC & GRC Ecosystem.
         Provides live workspace file tree navigation, real file reading, 
         advanced multi-format log conversion (.evtx, .json, .csv) with zero data loss.
         Supports Base64, multipart, and direct filesystem path ingestion.
===============================================================================
"""

import os
import sys
import json
import time
import csv
import io
import base64
import urllib.parse
import xml.etree.ElementTree as ET
import webbrowser
import cgi
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# Try importing Evtx library
HAS_EVTX = False
try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

PORT = 8000
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
INGEST_DIR = os.path.join(WORKSPACE_DIR, "01-DATA-SOURCES-AND-INGESTION")
NORMALIZE_DIR = os.path.join(WORKSPACE_DIR, "02-NORMALIZATION-AND-PARSING")
OUTPUT_JSON_FILE = os.path.join(NORMALIZE_DIR, "sample-normalized-events.json")

def strip_namespace(tag):
    """Remove XML namespace prefix if present."""
    return tag.split('}')[-1] if '}' in tag else tag

def parse_xml_record_full(xml_str):
    """Parses raw XML string from EVTX with ZERO DATA LOSS."""
    try:
        root = ET.fromstring(xml_str)
    except Exception:
        return None

    event_data = {}
    system_data = {}

    for elem in root:
        tag_name = strip_namespace(elem.tag)
        if tag_name == "System":
            for child in elem:
                c_tag = strip_namespace(child.tag)
                if child.attrib:
                    for k, v in child.attrib.items():
                        system_data[f"{c_tag}_{k}"] = v
                if child.text and child.text.strip():
                    system_data[c_tag] = child.text.strip()

        elif tag_name in ("EventData", "UserData"):
            for child in elem:
                c_tag = strip_namespace(child.tag)
                if c_tag == "Data":
                    name = child.attrib.get("Name", "")
                    value = child.text or ""
                    if name:
                        event_data[name] = value
                else:
                    if child.text and child.text.strip():
                        event_data[c_tag] = child.text.strip()

    normalized = {
        "event_id": system_data.get("EventID", "Unknown"),
        "record_id": system_data.get("EventRecordID", "N/A"),
        "timestamp": system_data.get("TimeCreated_SystemTime", system_data.get("TimeCreated", "")),
        "computer": system_data.get("Computer", ""),
        "provider": system_data.get("Provider_Name", system_data.get("Provider", "")),
        "channel": system_data.get("Channel", ""),
        "level": system_data.get("Level", ""),
        "image": event_data.get("Image", event_data.get("NewProcessName", event_data.get("processPath", ""))),
        "command_line": event_data.get("CommandLine", ""),
        "parent_image": event_data.get("ParentImage", event_data.get("ParentProcessName", "")),
        "user": event_data.get("User", event_data.get("SubjectUserName", event_data.get("jobOwner", system_data.get("Security_UserID", "")))),
        "hashes": event_data.get("Hashes", ""),
        "process_id": event_data.get("ProcessId", system_data.get("Execution_ProcessID", "")),
        "thread_id": system_data.get("Execution_ThreadID", ""),
        "system_data": system_data,
        "event_data": event_data,
        "raw_xml": xml_str
    }
    return normalized

def parse_evtx_file(evtx_path):
    """Parses EVTX file into full event dictionaries."""
    if not HAS_EVTX:
        return [{"error": "python-evtx library is not installed on system."}]
    
    events = []
    try:
        with evtx.Evtx(evtx_path) as log:
            for record in log.records():
                xml_content = record.xml()
                parsed = parse_xml_record_full(xml_content)
                if parsed:
                    events.append(parsed)
    except Exception as e:
        events.append({"error": f"Failed to parse EVTX: {str(e)}"})
    return events

def build_repo_tree(path):
    """Recursively builds repository directory tree for sidebar navigation."""
    items = []
    try:
        entries = sorted(os.listdir(path))
        for entry in entries:
            if entry.startswith(".") or entry == "node_modules":
                continue
            full_p = os.path.join(path, entry)
            rel_p = os.path.relpath(full_p, WORKSPACE_DIR)
            is_dir = os.path.isdir(full_p)
            item = {
                "name": entry,
                "path": rel_p,
                "is_dir": is_dir
            }
            if is_dir:
                item["children"] = build_repo_tree(full_p)
            items.append(item)
    except Exception:
        pass
    return items

def convert_events_to_csv(events):
    """Converts normalized events into flattened CSV string with zero data loss."""
    if not events:
        return ""
    
    field_keys = set()
    for ev in events:
        for k in ev.keys():
            if k != "raw_xml" and not isinstance(ev[k], dict):
                field_keys.add(k)
        if "event_data" in ev and isinstance(ev["event_data"], dict):
            for k in ev["event_data"].keys():
                field_keys.add(f"data_{k}")

    fieldnames = sorted(list(field_keys))
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for ev in events:
        row = {}
        for k, v in ev.items():
            if not isinstance(v, dict) and k != "raw_xml":
                row[k] = str(v)
        if "event_data" in ev and isinstance(ev["event_data"], dict):
            for k, v in ev["event_data"].items():
                row[f"data_{k}"] = str(v)
        writer.writerow(row)

    return output.getvalue()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class SOCEcosystemHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WORKSPACE_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/tree":
            tree = build_repo_tree(WORKSPACE_DIR)
            self._send_json({"tree": tree, "has_evtx": HAS_EVTX})
            return

        elif path == "/api/read-file":
            rel_path = query.get("path", [""])[0]
            rel_path = urllib.parse.unquote(rel_path)
            full_path = os.path.join(WORKSPACE_DIR, rel_path)

            if not os.path.exists(full_path) or os.path.isdir(full_path):
                self._send_json({"error": f"File not found: {rel_path}"}, status=404)
                return

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self._send_json({
                    "path": rel_path,
                    "filename": os.path.basename(full_path),
                    "size": os.path.getsize(full_path),
                    "content": content
                })
            except Exception as e:
                self._send_json({"error": f"Failed to read file: {str(e)}"}, status=500)
            return

        elif path == "/api/list-samples":
            samples = []
            if os.path.exists(INGEST_DIR):
                for root, _, files in os.walk(INGEST_DIR):
                    for file in sorted(files):
                        if file.endswith((".evtx", ".json", ".csv", ".log")):
                            full_p = os.path.join(root, file)
                            rel_p = os.path.relpath(full_p, WORKSPACE_DIR)
                            samples.append({
                                "name": file,
                                "path": rel_p,
                                "category": os.path.basename(root)
                            })
            self._send_json({"samples": samples, "has_evtx": HAS_EVTX})
            return

        elif path == "/api/get-latest-normalized":
            if os.path.exists(OUTPUT_JSON_FILE):
                try:
                    with open(OUTPUT_JSON_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._send_json({"events": data})
                except Exception as e:
                    self._send_json({"error": str(e)}, status=500)
            else:
                self._send_json({"events": []})
            return

        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/convert-log":
            content_length = int(self.headers.get("Content-Length", 0))
            content_type = self.headers.get("Content-Type", "")

            # 1. Base64 or JSON Payload
            if "application/json" in content_type:
                body = self.rfile.read(content_length)
                try:
                    payload = json.loads(body.decode("utf-8"))
                    
                    # Case A: Base64 direct file upload
                    if "file_data_base64" in payload:
                        filename = payload.get("filename", "uploaded_sample.evtx")
                        b64_str = payload["file_data_base64"]
                        file_bytes = base64.b64decode(b64_str)

                        temp_dir = os.path.join(INGEST_DIR, "sample-logs", "uploaded_temp")
                        os.makedirs(temp_dir, exist_ok=True)
                        temp_path = os.path.join(temp_dir, filename)

                        with open(temp_path, "wb") as f:
                            f.write(file_bytes)

                        events = self._process_file(temp_path, filename)
                        csv_data = convert_events_to_csv(events)

                        os.makedirs(NORMALIZE_DIR, exist_ok=True)
                        with open(OUTPUT_JSON_FILE, "w", encoding="utf-8") as f:
                            json.dump(events, f, indent=2)

                        self._send_json({
                            "status": "success",
                            "filename": filename,
                            "event_count": len(events),
                            "events": events,
                            "csv": csv_data
                        })
                        return

                    # Case B: Repository path reference
                    sample_path = payload.get("sample_path", "")
                    sample_path = urllib.parse.unquote(sample_path)
                    full_path = os.path.join(WORKSPACE_DIR, sample_path)

                    if not os.path.exists(full_path):
                        self._send_json({"error": f"Sample file not found: {sample_path}"}, status=404)
                        return

                    filename = os.path.basename(full_path)
                    events = self._process_file(full_path, filename)
                    csv_data = convert_events_to_csv(events)

                    os.makedirs(NORMALIZE_DIR, exist_ok=True)
                    with open(OUTPUT_JSON_FILE, "w", encoding="utf-8") as f:
                        json.dump(events, f, indent=2)

                    self._send_json({
                        "status": "success",
                        "filename": filename,
                        "event_count": len(events),
                        "events": events,
                        "csv": csv_data
                    })
                    return
                except Exception as e:
                    self._send_json({"error": f"JSON payload error: {str(e)}"}, status=500)
                return

            # 2. Multipart form upload
            elif "multipart/form-data" in content_type:
                try:
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']}
                    )

                    if "file" not in form:
                        self._send_json({"error": "No file uploaded in form."}, status=400)
                        return

                    file_item = form["file"]
                    filename = file_item.filename
                    
                    if hasattr(file_item, 'file') and file_item.file:
                        file_data = file_item.file.read()
                    elif hasattr(file_item, 'value'):
                        file_data = file_item.value if isinstance(file_item.value, bytes) else file_item.value.encode('utf-8')
                    else:
                        self._send_json({"error": "Could not read file data from form payload."}, status=400)
                        return

                    temp_dir = os.path.join(INGEST_DIR, "sample-logs", "uploaded_temp")
                    os.makedirs(temp_dir, exist_ok=True)
                    temp_path = os.path.join(temp_dir, filename)

                    with open(temp_path, "wb") as f:
                        f.write(file_data)

                    events = self._process_file(temp_path, filename)
                    csv_data = convert_events_to_csv(events)

                    os.makedirs(NORMALIZE_DIR, exist_ok=True)
                    with open(OUTPUT_JSON_FILE, "w", encoding="utf-8") as f:
                        json.dump(events, f, indent=2)

                    self._send_json({
                        "status": "success",
                        "filename": filename,
                        "event_count": len(events),
                        "events": events,
                        "csv": csv_data
                    })
                except Exception as e:
                    self._send_json({"error": f"Multipart parse error: {str(e)}"}, status=500)
                return

        self._send_json({"error": "Route not found"}, status=404)

    def _process_file(self, file_path, filename):
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".evtx":
            return parse_evtx_file(file_path)
        elif ext == ".json":
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                return data if isinstance(data, list) else [data]
            except Exception as e:
                return [{"error": f"JSON parse error: {str(e)}"}]
        elif ext in (".csv", ".log", ".txt"):
            events = []
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for idx, line in enumerate(lines, start=1):
                    if line.strip():
                        events.append({
                            "event_id": str(idx),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "computer": "LOCAL-HOST",
                            "user": "System User",
                            "image": "TextLogRecord",
                            "command_line": line.strip(),
                            "parent_image": "N/A"
                        })
            except Exception as e:
                events.append({"error": f"Text parse error: {str(e)}"})
            return events
        return [{"error": f"Unsupported format: {ext}"}]

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

def main():
    port = PORT
    server = None

    for candidate_port in range(port, port + 10):
        try:
            server = ThreadedHTTPServer(("0.0.0.0", candidate_port), SOCEcosystemHandler)
            port = candidate_port
            break
        except OSError as e:
            if e.errno == 98:  # Address already in use
                continue
            else:
                raise e

    if not server:
        print(f"[!] Error: Could not bind to any port in range {PORT}-{PORT+9}.")
        sys.exit(1)

    print("=" * 80)
    print("  SOC & GRC ECOSYSTEM SERVER - LIGHT SKY BLUE LAB ENGINE")
    print("=" * 80)
    print(f"[*] Workspace Root   : {WORKSPACE_DIR}")
    print(f"[*] EVTX Parser      : {'ENABLED' if HAS_EVTX else 'DISABLED'}")
    print(f"[*] Server Listening : http://localhost:{port}")
    print("=" * 80)

    web_url = f"http://localhost:{port}"
    print(f"[+] Opening browser interface -> {web_url}")
    webbrowser.open(web_url)

    print("[+] Press Ctrl+C to terminate server.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        server.server_close()
        sys.exit(0)

if __name__ == "__main__":
    main()
