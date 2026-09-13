# Mapper — Project Architecture & Scan Pipeline Flowcharts

This document provides visual flowcharts describing the **Mapper Vulnerability Scanner** system architecture, execution pipeline, and decision logic for hackathon presentation slides and project documentation.

---

## 1. High-Level System Architecture Flowchart

```mermaid
flowchart TB
    subgraph ClientLayer ["Client & Interface Layer"]
        UI["Web Dashboard UI (SPA)\n[Port 8081]"]
        CLI["CLI / REST Clients"]
    end

    subgraph APILayer ["API & Control Layer (backend/app.py)"]
        AUTH["JWT Authentication &\nUser Session Management"]
        API["Flask REST API Engine\n[Port 5001]"]
        STATS["Dashboard Analytics\n& Job Monitor"]
    end

    subgraph CoreEngine ["Scan Orchestrator Engine (backend/scanner/orchestrator.py)"]
        JOB["Job Queue & Thread Lifecycle Manager"]
        FETCHER["Async HTTP Engine (aiohttp)\nRate Limiting & Auth Injection"]
        NORM["Response Normalizer\n(PageSnapshot Object)"]
    end

    subgraph InspectionPipeline ["Analysis & Detection Pipeline"]
        PASSIVE["Passive Signature Matcher\n& Security Checks"]
        SURFACE["Attack Surface Extractor\n(GET Params & POST Forms)"]
        ACTIVE["Active Probe Engine\n(XSS, SQLi, LFI, CRLF Canaries)"]
    end

    subgraph ProcessingLayer ["Correlation & Scoring Engine"]
        CORR["Finding Correlator\n& Deduplicator"]
        ENRICH["CVSS v3.1 Engine\n& Mitigation Mapper"]
        RISK["Composite Risk Scorer\n(0-100 Score & Grade A+ to F)"]
    end

    subgraph StorageLayer ["Persistence & Export Layer"]
        STORAGE["ScanStorage Manager Driver"]
        ES[("Elasticsearch 8.x Cluster\n(scan-metadata & scan-results)")]
        MEM[("Thread-Safe In-Memory Store\n(Fallback Storage)")]
        EXPORTER["Report Generator\n(JSON & Dark HTML Export)"]
    end

    UI <-->|HTTP / JWT| API
    CLI <-->|HTTP API| API
    API --> AUTH
    API --> STATS
    API -->|Submit Scan Job| JOB

    JOB --> FETCHER
    FETCHER --> NORM
    NORM --> PASSIVE
    NORM --> SURFACE
    SURFACE --> ACTIVE
    ACTIVE --> FETCHER

    PASSIVE --> CORR
    ACTIVE --> CORR
    CORR --> ENRICH
    ENRICH --> RISK

    RISK --> STORAGE
    STORAGE -->|Primary| ES
    STORAGE -.->|Fallback| MEM

    STORAGE --> EXPORTER
    EXPORTER --> UI
```

---

## 2. Detailed Scan Execution Pipeline Flowchart

```mermaid
flowchart TD
    Start([User Initiates Scan]) --> Submit[POST /api/scans/start]
    Submit --> CreateJob[Create ScanJob: State = QUEUED]
    CreateJob --> SpawnThread[Spawn Background Async Worker Thread]
    
    subgraph AsyncPipeline ["Async Pipeline Execution"]
        SpawnThread --> Stage1[Stage 1: State = FETCHING\nAsync HTTP GET Main Target URL]
        Stage1 --> CheckReach{Target Reachable?}
        CheckReach -- No --> FailJob[Set State = FAILED\nRecord Connection Error] --> EndFail([Scan Stopped])
        
        CheckReach -- Yes --> Stage2[Stage 2: State = ANALYZING\nNormalize Response to PageSnapshot]
        
        Stage2 --> Stage3{Deep Scan Enabled?}
        Stage3 -- Yes --> DeepCheck[Probe Sensitive Paths\n.git, .env, robots.txt, admin]
        Stage3 -- No --> Stage4
        DeepCheck --> Stage4[Stage 4: Passive Pattern Matching\nRegex + Nuclei Rules + Header Checks]
        
        Stage4 --> Stage5[Stage 5: Surface Extraction\nExtract Query Params & Form Bodies]
        
        Stage5 --> Stage6Mode{Scan Mode?}
        Stage6Mode -- Passive Only --> Stage7
        Stage6Mode -- Light / Full Active --> Stage6Active[Stage 6: State = ACTIVE_PROBING\nRun Async Active Probe Suite]
        
        Stage6Active --> Stage7[Stage 7: State = CORRELATING\nDeduplicate & Group Findings]
        
        Stage7 --> Stage8[Stage 8: CVSS v3.1 Metric Enrichment\n& Mitigation Association]
        Stage8 --> Stage9[Stage 9: Calculate Risk Score & Grade]
    end

    Stage9 --> StoreResults[Stage 10: Store Job & Findings via ScanStorage]
    StoreResults --> SetComplete[Set State = COMPLETED, Progress = 100%]
    SetComplete --> EndSuccess([Report Ready on Dashboard])
```

---

## 3. Active Probe Injection Decision Flowchart

```mermaid
flowchart TD
    ParamInput([Extracted Target Parameter]) --> SourceCheck{Parameter Source?}
    
    SourceCheck -- "query_url (GET)" --> SetupGET[Construct Query Parameter URL]
    SourceCheck -- "form_post (POST)" --> SetupPOST[Construct Form Payload Dictionary]
    
    SetupGET --> SelectProbe[Select Active Vulnerability Probe]
    SetupPOST --> SelectProbe
    
    subgraph Probes ["Active Probe Suite"]
        SelectProbe --> ProbeXSS[1. Reflected XSS Probe\nInject Canary: UUID + quote/bracket]
        SelectProbe --> ProbeSQLi[2. Error-Based SQLi Probe\nInject Single Quote ']
        SelectProbe --> ProbeBSQLi[3. Time-Based Blind SQLi Probe\nInject SLEEP/pg_sleep/WAITFOR]
        SelectProbe --> ProbeLFI[4. LFI / Path Traversal Probe\nInject ../etc/passwd or win.ini]
        SelectProbe --> ProbeCRLF[5. CRLF Injection Probe\nInject %0d%0a Header Marker]
    end
    
    MethodCheck{Method?} -- POST --> ExecPOST[Send HTTP POST via fetcher.fetch_post]
    MethodCheck{Method?} -- GET --> ExecGET[Send HTTP GET via fetcher.fetch]
    
    ExecPOST --> Eval[Evaluate HTTP Status, Body & Delays]
    ExecGET --> Eval
    
    Eval --> VulnCheck{Signature / Canary / Delay Matched?}
    VulnCheck -- Yes --> LogVuln[Mark Parameter Vulnerable\nGenerate Finding Object + Proof Log]
    VulnCheck -- No --> LogSafe[Mark Parameter Safe\nRecord Probe Execution Log]
    
    LogVuln --> CollectLogs[Collect Probe Logs & Findings]
    LogSafe --> CollectLogs
    CollectLogs --> ReturnResult([Return to Orchestrator Pipeline])
```

---

### Key Takeaways for Presentation:
* **Asynchronous Speed**: Utilizes `asyncio` gather loops to parallelize network probes.
* **Dual Injection Capability**: Supports both URL query injection (`GET`) and form payload injection (`POST`).
* **Resilient Architecture**: Fallback mechanism ensures continuous scan operation even when Elasticsearch is unavailable.
