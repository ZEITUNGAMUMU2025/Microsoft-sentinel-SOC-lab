# Microsoft-sentinel-SOC-lab
Built a hands-on Microsoft Sentinel SOC lab to simulate and detect suspicious activity on a Windows endpoint.


# Microsoft Sentinel SOC Lab — Windows Failed Logon Detection & Incident Investigation
Hands-on SOC lab demonstrating Windows security event collection, KQL-based authentication investigation, Event ID 4625 failed-logon detection, a scheduled analytics rule, MITRE ATT&CK mapping, and Microsoft Defender incident investigation

# OBJECTIVES
- The main objectives of this lab were to:-
- Deploy and configure Microsoft Sentinel.
- Connect a Windows endpoint for security event collection.
- Validate Windows Security event ingestion.
- Investigate authentication activity using KQL.
- Identify failed logon attempts using Event ID 4625.
- Create a scheduled Microsoft Sentinel analytics rule.
- Configure threshold-based detection logic.
- Map the detection to MITRE ATT&CK.
- Enable incident creation.
- Understand Sentinel's integration with Microsoft Defender.



# LAB ARCHITECTURE

``` text
┌──────────────────────────┐
│     Windows Endpoint     │
│    WIN-SOC-ENDPOINT      │
│                          │
│ Windows Security Events  │
│ Event ID 4625            │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│     Log Analytics        │
│  law-sentinel-soc-lab    │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│    Microsoft Sentinel    │
│                          │
│ KQL Investigation        │
│ Analytics Rules          │
│ Alerts / Incidents       │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ Microsoft Defender       │
│ Unified SecOps Portal    │
└──────────────────────────┘
```


# 1. Log Ingestion Validation
The first task was to determine whether Windows telemetry was actually
reaching Sentinel.

Initial highly restrictive queries returned no results. Rather than
assuming the connector was broken, I widened the investigation to
`SecurityEvent` table.

``` kql
SecurityEvent
| where TimeGenerated > ago(7d)
| project TimeGenerated, Computer, EventID, Account
| order by TimeGenerated desc
| take 50
```

This returned events from `WIN-SOC-ENDPOINT`, including Event IDs such
as:

-   `4625` --- failed logon
-   `4624` --- successful logon
-   `4688` --- process creation
-   `4673` --- privileged service operation

This established that Windows security telemetry was being collected
successfully.

![KQL results showing `SecurityEvent` records
from `WIN-SOC-ENDPOINT`.](https://i.imgur.com/XEcukte.jpeg).
### Figure 1 — Windows Security events successfully ingested into Microsoft Sentinel through Log Analytics.





# 2. Investigating Failed Logons

After validating the data source, I focused on Windows Event ID 4625.

Event ID 4625 represents a failed logon attempt and can be useful for identifying suspicious authentication behavior such as password guessing or brute-force activity.

The initial investigation query was:

``` kql
SecurityEvent
| where Computer == "WIN-SOC-ENDPOINT"
| where EventID == 4625
| summarize FailedLogons=count() by Account, IpAddress
| order by FailedLogons desc
```

nitially, this query returned no results.

Instead of assuming that Event ID 4625 was unavailable, I expanded the time range and removed restrictive filters.

This investigation confirmed that Event ID 4625 was present in the environment.

Observed accounts included examples such as:

\user
\test
\admin
\administrator

his provided authentication activity that could be used to build and test a detection.



# 3.  KQL Investigation

The broader investigation query was:
``` kql
SecurityEvent
| where TimeGenerated > ago(7d)
| project TimeGenerated, Computer, EventID, Account
| order by TimeGenerated desc
| take 50
```

The results showed multiple authentication-related events on  :
WIN-SOC-ENDPOINT

This troubleshooting process demonstrated an important SOC principle:
> **A query returning no results does not automatically mean that the
> data source is broken.**

Possible causes include:

-   Incorrect time range
-   Incorrect hostname
-   Incorrect field
-   Overly restrictive filters
-   No matching activity
-   Data ingestion problems
 The investigation progressively widened the query before reintroducing
filters.


# 4.  Detection Engineering
After confirming that the required telemetry was available, I created a Microsoft Sentinel scheduled analytics rule.

## Analytics Rule Configuration
The analytics rule was configured with:

-  Medium severity
-  Enabled status
-  5-minute execution frequency
-  10-minute lookback period
-  Incident creation enabled
-  Account entity mapping
-  Host entity mapping
-  IP entity mapping
-  MITRE ATT&CK classification

The rule successfully passed Sentinel's validation process.

![ Microsoft Sentinel analytics rule successfully validated and configured for repeated failed logon detection.](https://i.imgur.com/nQPdcLo.png).
### Figure 2 — Microsoft Sentinel analytics rule successfully validated and configured for repeated failed logon detection.


# 7. MITRE ATT&CK Mapping

The detection was associated with the Credential Access tactic within MITRE ATT&CK.
The scenario focuses on repeated failed authentication attempts that may indicate password guessing or brute-force behavior.
MITRE mapping helps analysts understand the behavior from an attacker-technique perspective rather than treating the event as an isolated log entry.








