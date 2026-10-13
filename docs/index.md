<p class="project-kicker">Workload identity / mTLS</p>

# Check who connects before serving a tool.

<p class="project-lead">Embed identity checks in an MCP gateway. Callers prove who they are with short-lived certificates; unapproved connections are refused.</p>

## How it works

```mermaid
---
config:
  theme: base
  themeVariables:
    primaryTextColor: '#183452'
    textColor: '#183452'
    lineColor: '#7b8797'
    edgeLabelBackground: '#e8effa'
    fontFamily: 'Arial, sans-serif'
    fontSize: '15px'
  flowchart:
    nodeSpacing: 24
    rankSpacing: 28
    padding: 12
---
flowchart TB
    accTitle: Certificate-based caller checks at an MCP gateway
    accDescr: SPIRE streams certificates and trusted roots into the embedded bridge. The caller connects with mutual TLS. The bridge checks identity and the allowlist before serving the MCP request. Credential loss or updates close affected connections.
    S["SPIRE<br/>Certificates and trusted roots"] --> B["Bridge inside your gateway"]
    C["Caller with a certificate"] -->|Mutual TLS| B
    B --> D{"Identity allowed?"}
    D -->|Yes| M["Serve the MCP request"]
    D -->|No| N["Refuse connection"]
    classDef source fill:#e8effa,stroke:#5276a2,color:#183452,stroke-width:1.5px
    classDef core fill:#e0f3ec,stroke:#328267,color:#173f33,stroke-width:1.5px
    classDef limit fill:#fff0dc,stroke:#b27b36,color:#63421d,stroke-width:1.5px
    class S,C source
    class B,D,M core
    class N limit
```

[Demo guide](kubernetes-lab.md){ .overview-link }
[Certificate lifecycle](credential-lifecycle.md){ .overview-link }
[Readiness and limits](publication-readiness.md){ .overview-link }

!!! note "Scope"
    Local review only; not published yet. Tool permissions remain a separate OAuth boundary.
