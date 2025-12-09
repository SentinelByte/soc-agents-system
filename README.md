# TriAgen

Automated Alert Triage Engine

TriAgen is a local, privacy-safe ai agent for automating the steps of SOC alert handling. It receives alerts, collects evidence from the host, analyzes the situation, and produces a structured triage decision.
Designed for security engineers who want a small, modular, testable triage engine that runs fully on their own machine.

---

### Core Purpose

TriAgen automates early-stage alert triage:

1. Takes an alert (from file, CLI, or REST API)
2. Runs local evidence collection
3. Analyzes the context
4. Assigns severity and a verdict
5. Suggests a response action
6. Stores everything for auditing and testing

---

### System Overview

***Alert → Alert Processor → Enrichment Engine → Reasoning Agent → Response Recommender → Output + Audit Logs***

### Main Components

**Alert Processor**

* Validates alert fields
* Normalizes structure
* Routes alert to the correct investigation type (process, command, network, file, auth)

**Enrichment Engine (Local Collection Tools)**
Runs local checks such as:

* List running processes
* Inspect network connections
* Compute file hashes
* Review recent logs
* Search for related activity
* Persistence checks
  Returns structured JSON.

**Reasoning Engine**
Uses the alert + enrichment results to:

* Explain the activity
* Map to MITRE ATT&CK
* Assign severity
* Mark as benign or malicious
* Produce a triage summary

**Response Recommender**
Suggests a local response:

* Kill process
* Block IP
* Quarantine file
* Mark as false positive
* Escalate

**Audit & Logging**
Stores:

* Raw alert
* Enrichment data
* Reasoning summary
* Recommended action
* Timestamps

---

### Supported Input Methods

TriAgen can receive alerts in **three ways**:

**A. File-Based Input**

Useful for batch testing.

```
triagen --alert-file ./alerts/sample_alert.json
```

**B. CLI / Script Input**

Useful for manual or automated pipelines.

```
triagen --alert '{ "alert_type": "process_start", "user": "alice", ... }'
```

We accept either raw JSON or a file path.

**C. Local REST API (Optional)**

Useful for integrating with SIEM/SOAR or other tools.

Start the API:

```
triagen api --port 8080
```

Send an alert:

```
POST /alert
Content-Type: application/json
{
  "alert_type": "network_connection",
  "hostname": "workstation-01",
  "raw_log": "..."
}
```

API returns the full triage result.

---

### Minimal Alert Format

TriAgen expects at least:

```json
{
  "alert_type": "process_start",
  "timestamp": "2025-01-01T12:00:00Z",
  "user": "bob",
  "hostname": "host1",
  "process": "powershell.exe -nop -w hidden",
  "raw_log": "original log line..."
}
```

Fields may vary by alert type.

---

### Output Format

TriAgen produces:

1. A JSON triage decision
2. A Markdown summary
3. Stored log files for auditing

Example JSON:

```json
{
  "severity": "high",
  "verdict": "likely malware",
  "attack_technique": "T1059.004",
  "recommended_action": "kill_process",
  "confidence": 0.92
}
```

Example Markdown summary:

```
### Triage Summary
Severity: High  
Verdict: Likely malware  
Technique: T1059.004 (Reverse Shell)  
Recommended Action: Kill process  
Confidence: 92%
```

---

### Execution Flow

1. Receive alert
2. Normalize alert
3. Perform local enrichment
4. Analyze findings
5. Produce triage output
6. Store logs
7. SUggest possible mitigations

---

*SentinelByte | AI Agent | 2025*
---