# System Boundary Diagram

This is a **system boundary and trust boundary** view of the governed corridor.

> Format: Mermaid (renders in GitHub and many doc pipelines).

```mermaid
flowchart LR
  %% Trust boundaries
  subgraph U[Untrusted Zone]
    UI[User / External Caller]
    EXT[External Inputs\n(text, files, tool outputs)]
  end

  subgraph G[Governed Runtime (Trusted Computing Base)]
    CIF_IN[CIF ingress\n(sanitize + label + size limits)]
    CDI_A[CDI action\n(allow/deny/degrade)]
    K[kernel\n(single chokepoint)]
    CDI_O[CDI output\n(output decision)]
    CIF_OUT[CIF egress\n(redact + leak budget)]

    subgraph S[State + Evidence Stores]
      SS[system_state]
      TOK[active capability tokens]
      LOG[audit receipts ledger]
      MEM[memory partitions\n(ephemeral / custodied / commitments / quarantine)]
    end

    CIF_IN --> CDI_A --> K --> CDI_O --> CIF_OUT
    CIF_IN --- SS
    CDI_A --- SS
    K --- SS
    K --- TOK
    K --- LOG
    K --- MEM
    CDI_O --- SS
    CIF_OUT --- SS
  end

  subgraph X[External Systems (Untrusted by default)]
    MODEL[Model Vendor API]
    TOOLS[Tools / Services]
    NET[Network I/O]
  end

  UI --> CIF_IN
  EXT --> CIF_IN
  CIF_OUT --> UI

  %% Mediation path
  K -->|capability token + adapter verify| MODEL
  K -->|capability token + adapter verify| TOOLS
  K -->|capability token + adapter verify| NET

  %% Anti-bypass note
  MODEL -. no direct calls .- UI
  TOOLS -. no direct calls .- UI
  NET -. no direct calls .- UI
```

## Boundary statements (auditor-oriented)

- The only permitted path to side effects is: **CIF → CDI → kernel → CDI → CIF**.
- The only permitted egress to external systems is via **kernel adapters** that verify a **capability token**.
- CIF and CDI are *not* “policy in prose”; they are **mechanical gates**.
- If any dependency needed for governance is missing or invalid, the runtime must **fail-closed**.
