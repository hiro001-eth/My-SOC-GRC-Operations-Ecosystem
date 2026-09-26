/* ===============================================================================
   SOC & GRC ECOSYSTEM - WORKBENCH ENGINE
   OPERATIONS IDE & ARCHITECTURAL INDEX ENGINE
   MAINTAINED BY MANJIL KATUWAL | SECURITY ENGINEER
   =============================================================================== */

let currentView = "workspace";
let currentNormalizedJson = null;
let currentCsvData = null;
let currentFormat = "json";
let isConverterInitialized = false;
let hasConvertedInSession = false;

document.addEventListener("DOMContentLoaded", () => {
  initGlobalDragAndDropPrevent();
  initNav();
  initResizers();
  loadRepoTree();
  initConverterLab();
});

/* Prevent browser from opening dropped files in the window tab.
   IMPORTANT: Allow events that target the dropzone to propagate naturally. */
function initGlobalDragAndDropPrevent() {
  const dropzoneEl = document.getElementById("logDropzone");
  window.addEventListener("dragover", (e) => {
    if (dropzoneEl && dropzoneEl.contains(e.target)) return;
    e.preventDefault();
  }, false);
  window.addEventListener("drop", (e) => {
    if (dropzoneEl && dropzoneEl.contains(e.target)) return;
    e.preventDefault();
  }, false);
}

/* --- SPLIT PANE RESIZER DRAG CONTROLLER --- */
function initResizers() {
  setupSplitResizer("resizer1", "pane1", "left");
  setupSplitResizer("resizer2", "pane3", "right");
  setupSplitResizer("resizerConverter", "converterPaneLeft", "left");
}

function setupSplitResizer(resizerId, targetPaneId, direction) {
  const resizer = document.getElementById(resizerId);
  const targetPane = document.getElementById(targetPaneId);
  if (!resizer || !targetPane) return;

  let x = 0;
  let w = 0;

  const onMouseMove = (e) => {
    const dx = e.clientX - x;
    const newWidth = direction === "left" ? w + dx : w - dx;
    if (newWidth > 140 && newWidth < 800) {
      targetPane.style.width = `${newWidth}px`;
    }
  };

  const onMouseUp = () => {
    resizer.classList.remove("dragging");
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
  };

  resizer.addEventListener("mousedown", (e) => {
    x = e.clientX;
    w = targetPane.getBoundingClientRect().width;
    resizer.classList.add("dragging");
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
  });
}

/* --- NAVIGATION & VIEW CONTROLLER --- */
function initNav() {
  const btns = document.querySelectorAll(".nav-btn");
  btns.forEach(btn => {
    btn.addEventListener("click", () => {
      const view = btn.getAttribute("data-view");
      switchView(view);
      btns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
    });
  });
}

function switchView(view) {
  currentView = view;
  const ws = document.getElementById("workspaceView");
  const log = document.getElementById("logView");
  const sidebarTitle = document.getElementById("sidebarTitle");

  if (ws) ws.style.display = "none";
  if (log) log.style.display = "none";

  if (view === "workspace") {
    if (ws) ws.style.display = "flex";
    if (sidebarTitle) sidebarTitle.textContent = "REPOSITORY EXPLORER";

  } else if (view === "logs") {
    if (log) log.style.display = "flex";
    if (sidebarTitle) sidebarTitle.textContent = "CONVERTER EXPLORER";
  }
}

/* --- REPOSITORY TREE EXPLORER & LIVE DISK READER --- */
function loadRepoTree() {
  fetch("/api/tree")
    .then(res => res.json())
    .then(data => {
      const treeNav = document.getElementById("repoTreeNav");
      if (!treeNav) return;

      if (data.tree) {
        treeNav.innerHTML = renderTreeNodes(data.tree);

        // Folder toggle listeners
        treeNav.querySelectorAll(".tree-folder-title").forEach(title => {
          title.addEventListener("click", (e) => {
            e.stopPropagation();
            const sub = title.nextElementSibling;
            if (sub) {
              sub.style.display = sub.style.display === "none" ? "block" : "none";
            }
          });
        });

        // File click & drag-start listeners
        treeNav.querySelectorAll(".tree-file-item").forEach(item => {
          item.addEventListener("click", (e) => {
            e.stopPropagation();
            treeNav.querySelectorAll(".tree-file-item").forEach(x => x.classList.remove("active"));
            item.classList.add("active");

            const filePath = item.getAttribute("data-path");
            
            if (currentView === "logs" && (filePath.endsWith(".evtx") || filePath.endsWith(".json") || filePath.endsWith(".csv") || filePath.endsWith(".log"))) {
              processSelectedSample(filePath);
            } else {
              readLiveFile(filePath);
            }
          });

          // Enable dragging sidebar files into dropzone
          item.addEventListener("dragstart", (e) => {
            const filePath = item.getAttribute("data-path");
            e.dataTransfer.setData("text/plain", filePath);
          });
        });

        // Auto-read first file
        const firstFile = treeNav.querySelector(".tree-file-item");
        if (firstFile) {
          firstFile.classList.add("active");
          readLiveFile(firstFile.getAttribute("data-path"));
        }
      }
    })
    .catch(err => {
      console.warn("Tree fetch error:", err);
    });
}

function renderTreeNodes(nodes) {
  let html = "";
  nodes.forEach(n => {
    if (n.is_dir) {
      html += `
        <li class="tree-folder">
          <div class="tree-folder-title">${escape(n.name)} /</div>
          <ul class="tree-sub-list" style="display: none;">
            ${n.children ? renderTreeNodes(n.children) : ""}
          </ul>
        </li>
      `;
    } else {
      const isConvertible = n.name.endsWith(".evtx") || n.name.endsWith(".json") || n.name.endsWith(".csv") || n.name.endsWith(".log");
      html += `
        <li class="tree-file-item" data-path="${escape(n.path)}" draggable="true">
          <span>${escape(n.name)}</span>
          ${isConvertible ? '<span style="color: var(--accent-blue); font-size: 0.7rem;">[Convert]</span>' : ''}
        </li>
      `;
    }
  });
  return html;
}

function readLiveFile(filePath) {
  const codeViewer = document.getElementById("codeViewer");
  const codeViewerTitle = document.getElementById("codeViewerTitle");

  if (codeViewerTitle) codeViewerTitle.textContent = `FILE CONTENT: ${filePath}`;
  if (codeViewer) codeViewer.innerHTML = `<pre class="code-block"><code>[ Reading live file from disk... ]</code></pre>`;

  fetch(`/api/read-file?path=${encodeURIComponent(filePath)}`)
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        if (codeViewer) codeViewer.innerHTML = `<pre class="code-block"><code>[ Error reading file: ${data.error} ]</code></pre>`;
      } else {
        if (codeViewer) {
          codeViewer.innerHTML = `<pre class="code-block"><code>${escape(data.content || "[ Empty File ]")}</code></pre>`;
        }
        renderFileArchitectureContext(filePath, data.size);
      }
    })
    .catch(err => {
      if (codeViewer) codeViewer.innerHTML = `<pre class="code-block"><code>[ Network Error: ${err.message} ]</code></pre>`;
    });
}

function renderFileArchitectureContext(filePath, fileSize) {
  const contextViewer = document.getElementById("contextViewer");
  if (!contextViewer) return;

  let role = "Operational Architecture Artifact";
  let upstream = "Endpoint Agent / Collector";
  let downstream = "Log Ingestion / Detection Engine";
  let workflow = "Daily Security Operations & Control Verification";

  if (filePath.includes("01-DATA-SOURCES")) {
    role = "Log Telemetry Collector Pipeline & Collector Config";
    upstream = "Windows Event Log / Sysmon / Vector Agent";
    downstream = "02-NORMALIZATION-AND-PARSING / Logstash Parser";
    workflow = "Security Engineer configures telemetry agents to capture process execution (Event ID 1) and network sockets.";
  } else if (filePath.includes("02-NORMALIZATION")) {
    role = "Canonical Schema Field Taxonomy & Grok Parser";
    upstream = "01-DATA-SOURCES Ingestion Telemetry";
    downstream = "03-DETECTION-ENGINEERING / Elastic / SIEM Engine";
    workflow = "Normalizes raw vendor logs into unified ECS/OCSF fields (`process.name`, `command_line`, `user`).";
  } else if (filePath.includes("03-DETECTION")) {
    role = "Detection-as-Code Rule (Sigma / KQL / YARA)";
    upstream = "02-NORMALIZATION Unified Event Stream";
    downstream = "04-ALERT-LIFECYCLE-AND-TRIAGE / SOC Alert Queue";
    workflow = "Security Engineer (Manjil Katuwal) tests rule logic against attack samples to detect MITRE ATT&CK techniques.";
  } else if (filePath.includes("04-ALERT")) {
    role = "SOC Analyst Triage SOP Checklist & Severity Matrix";
    upstream = "03-DETECTION Fired Alerts Queue";
    downstream = "07-INCIDENT-RESPONSE & 08-FORENSICS";
    workflow = "Guides SOC Tier 1/2 analysts to verify True Positive indicators and execute initial containment protocols.";
  } else if (filePath.includes("11-GRC")) {
    role = "Regulatory Compliance & Security Audit Mapping";
    upstream = "09-EVIDENCE Locker SHA-256 Verification Logs";
    downstream = "External Auditor Sign-off / Executive CISO Matrix";
    workflow = "Provides empirical proof mapping security controls to NIST SP 800-53 (SI-4/IR-4), ISO 27001, and SOC 2.";
  }

  contextViewer.innerHTML = `
    <div class="context-section">
      <div class="context-label">FILE IDENTIFIER</div>
      <div class="context-value"><code>${escape(filePath)}</code></div>
      <div class="context-value" style="margin-top: 0.25rem;">Size: ${fileSize} bytes | Disk Synced</div>
    </div>

    <div class="context-section">
      <div class="context-label">ARCHITECTURAL ROLE & PURPOSE</div>
      <div class="context-value">${role}</div>
    </div>

    <div class="context-section">
      <div class="context-label">UPSTREAM PIPELINE SOURCE</div>
      <div class="context-value">${upstream}</div>
    </div>

    <div class="context-section">
      <div class="context-label">DOWNSTREAM DESTINATION</div>
      <div class="context-value">${downstream}</div>
    </div>

    <div class="context-section">
      <div class="context-label">ENGINEER OPERATIONAL WORKFLOW</div>
      <div class="context-value">${workflow}</div>
      <div class="context-value" style="margin-top: 0.35rem; color: var(--text-muted); font-size: 0.75rem;">Operated by: Manjil Katuwal | Security Engineer</div>
    </div>
  `;
}

/* ===============================================================================
   TELEMETRY LOG CONVERTER MODULE
   =============================================================================== */
function initConverterLab() {
  if (isConverterInitialized) return;
  isConverterInitialized = true;

  const dropzone = document.getElementById("logDropzone");
  const fileInput = document.getElementById("logFileInput");
  const btnDownloadJson = document.getElementById("btnDownloadJson");
  const btnDownloadCsv = document.getElementById("btnDownloadCsv");
  const pillJson = document.getElementById("pillJson");
  const pillCsv = document.getElementById("pillCsv");

  if (fileInput) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files.length > 0) {
        uploadAndProcessFile(e.target.files[0]);
        e.target.value = "";
      }
    });
  }

  if (dropzone) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eName => {
      dropzone.addEventListener(eName, preventDefaults, false);
    });
    ['dragenter', 'dragover'].forEach(eName => {
      dropzone.addEventListener(eName, () => dropzone.classList.add('dragover'), false);
    });
    ['dragleave', 'drop'].forEach(eName => {
      dropzone.addEventListener(eName, () => dropzone.classList.remove('dragover'), false);
    });

    dropzone.addEventListener('drop', handleFileDrop, false);
  }

  if (btnDownloadJson) btnDownloadJson.addEventListener('click', downloadJson);
  if (btnDownloadCsv) btnDownloadCsv.addEventListener('click', downloadCsv);

  if (pillJson) {
    pillJson.addEventListener("click", () => {
      currentFormat = "json";
      pillJson.classList.add("active");
      if (pillCsv) pillCsv.classList.remove("active");
      updateCodePreview();
    });
  }

  if (pillCsv) {
    pillCsv.addEventListener("click", () => {
      currentFormat = "csv";
      pillCsv.classList.add("active");
      if (pillJson) pillJson.classList.remove("active");
      updateCodePreview();
    });
  }

  updateDownloadButtonState();
}

function preventDefaults(e) {
  e.preventDefault();
  e.stopPropagation();
}

function handleFileDrop(e) {
  preventDefaults(e);

  const dt = e.dataTransfer;

  // 1. External OS file drop
  if (dt && dt.files && dt.files.length > 0) {
    uploadAndProcessFile(dt.files[0]);
    return;
  }

  // 2. Internal tree item drag & drop
  if (dt) {
    const samplePath = dt.getData("text/plain");
    if (samplePath) {
      if (samplePath.endsWith(".evtx") || samplePath.endsWith(".json") || samplePath.endsWith(".csv") || samplePath.endsWith(".log")) {
        processSelectedSample(samplePath);
      } else {
        showStatus(`Selected item is not a convertible log telemetry file: ${samplePath}`, "error");
      }
    }
  }
}

function uploadAndProcessFile(file) {
  showStatus(`Reading local file: ${file.name} ...`, "loading");

  const reader = new FileReader();
  reader.onload = function(e) {
    const dataUrl = e.target.result;
    const base64Data = dataUrl.split(",")[1];

    showStatus(`Converting binary payload for ${file.name} ...`, "loading");

    fetch("/api/convert-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: file.name,
        file_data_base64: base64Data
      })
    })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        showStatus(`Error: ${data.error}`, "error");
      } else {
        showStatus(`Converted ${data.filename} cleanly. ${data.event_count} telemetry records normalized.`, "success");
        currentNormalizedJson = data.events;
        currentCsvData = data.csv || "";
        hasConvertedInSession = true;
        updateDownloadButtonState();
        updateCodePreview();
      }
    })
    .catch(err => {
      showStatus(`Upload failed: ${err.message}`, "error");
    });
  };

  reader.onerror = function(err) {
    showStatus(`Failed to read local file: ${err}`, "error");
  };

  reader.readAsDataURL(file);
}

function processSelectedSample(samplePath) {
  showStatus(`Converting sample telemetry: ${samplePath} ...`, "loading");

  fetch("/api/convert-log", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sample_path: samplePath })
  })
  .then(res => res.json())
  .then(data => {
    if (data.error) {
      showStatus(`Error: ${data.error}`, "error");
    } else {
      showStatus(`Converted ${data.filename} cleanly. ${data.event_count} telemetry records normalized.`, "success");
      currentNormalizedJson = data.events;
      currentCsvData = data.csv || "";
      hasConvertedInSession = true;
      updateDownloadButtonState();
      updateCodePreview();
    }
  })
  .catch(err => {
    showStatus(`Processing failed: ${err.message}`, "error");
  });
}

function updateDownloadButtonState() {
  const btnJson = document.getElementById("btnDownloadJson");
  const btnCsv = document.getElementById("btnDownloadCsv");

  if (btnJson) btnJson.disabled = !hasConvertedInSession;
  if (btnCsv) btnCsv.disabled = !hasConvertedInSession;
}

function updateCodePreview() {
  const jsonCode = document.getElementById("normalizedJsonCode");
  if (!jsonCode) return;

  if (!hasConvertedInSession) {
    jsonCode.textContent = "// Select or drop a log file to convert telemetry into JSON or CSV...";
    return;
  }

  if (currentFormat === "json") {
    jsonCode.textContent = currentNormalizedJson ? JSON.stringify(currentNormalizedJson, null, 2) : "// No JSON data converted";
  } else if (currentFormat === "csv") {
    jsonCode.textContent = currentCsvData || "// CSV data empty";
  }
}

function downloadJson() {
  if (!hasConvertedInSession || !currentNormalizedJson) {
    alert("Please convert a log file first before downloading.");
    return;
  }
  const str = JSON.stringify(currentNormalizedJson, null, 2);
  downloadBlob(str, "sample-normalized-events.json", "application/json");
}

function downloadCsv() {
  if (!hasConvertedInSession || !currentCsvData) {
    alert("Please convert a log file first before downloading.");
    return;
  }
  downloadBlob(currentCsvData, "sample-normalized-events.csv", "text/csv");
}

function downloadBlob(content, filename, contentType) {
  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function showStatus(message, type) {
  const banner = document.getElementById("converterStatus");
  if (!banner) return;
  banner.textContent = message;
  banner.className = "status-banner";
  if (type) banner.classList.add(type);
  banner.style.display = "block";
}

function escape(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
