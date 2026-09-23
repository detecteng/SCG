"""
Seed dataset for the Security Coverage Graph.

A hand-authored *worked demonstration* estate for a hybrid enterprise
(on-prem Active Directory + Entra + multi-cloud + a web app). It is designed so
every coverage metric the paper reports has a concrete, security-credible story
— not a full app x TTP grid, but the *relevant* (asset, technique) instances a
detection engineer would actually model.

Abstraction rule (why these are the App nodes)
-----------------------------------------------
An App is modeled at the coarsest level whose members share the same telemetry
production, controls, and therefore coverage — a *coverage-equivalence class*.
That lands at different granularities for different asset kinds:

  * Named platforms carry vendor identity — Entra, AWS, GCP are distinct Apps
    because each emits different logs and has different controls. You cannot
    abstract above the product without losing the relationships.
  * The endpoint fleet cannot be modeled per-machine and is not homogeneous, so
    it splits into categories: EP-Cat-A (managed, EDR+Sysmon) vs EP-Cat-B
    (legacy/unmanaged, Windows Security only). They are separate classes
    *because* their telemetry differs — which is exactly what makes the T1 gap
    real rather than an aggregation artifact.

Coverage matrix (13 relevant instances)
----------------------------------------
Status follows the paper's §3.2 precedence: preventive control -> covered,
else operable detection -> partial, else gap (unknown needs unconfirmed
telemetry, which the seed has none of). "Mapped" is the same precedence with
every DETECTED_BY edge taken at face value — what a technique-mapping view
would claim for the instance.

    App        TTP        Detection(s)          Preventive control   Mapped → Effective    Thesis
    ─────────  ─────────  ────────────────────  ───────────────────  ────────────────────  ──────
    EP-Cat-A   T1566.002  phish-exec (op)       Safe-Links           covered               T1
    EP-Cat-B   T1566.002  —                     —                    gap                   T1 (concealed gap)
    EP-Cat-A   T1003.001  edr-cred + sysmon(op) Credential Guard     covered               T5 (redundant)
    EP-Cat-B   T1003.001  sysmon-lsass (FALSE)  —                    partial → gap         T2 (false coverage)
    AD         T1003.006  dcsync-repl (op)      —                    partial               T3 (single-source)
    Entra      T1078.004  impossible-travel(op) Conditional Access   covered               T3 (single-source)
    Entra      T1621      mfa-fatigue (op)      Conditional Access   covered
    AWS        T1078.004  assumerole (op)       PIM                  covered               T3 (single-source)
    AWS        T1580      ct-discovery (op)     —                    partial
    AWS        T1530      s3-mass-get (FALSE)   S3 Block Public Acc. covered → partial*    T2 (false coverage)
    GCP        T1078.004  —                     —                    gap                   T1 (concealed gap)
    GCP        T1530      gcs-exfil (FALSE)     —                    partial → gap         T2 (parallel false cov)
    Web App    T1190      webapp-exploit (op)   WAF ruleset          covered

    * computed covered; engineer override to partial (Block Public Access does
      not stop an authenticated mass download). AWS also runs a detective S3 DLP
      control, which does not affect status but matches MITRE M1057 for T4.

False coverage (detection powered by telemetry the at-risk app does NOT produce):
  - EP-Cat-B : T1003.001  → sysmon-lsass, powered by Sysmon (legacy host runs no Sysmon)
  - AWS      : T1530       → s3-mass-get, powered by CloudTrail S3 *data* events (not enabled)
  - GCP      : T1530       → gcs-exfil,   powered by GCP Data Access logs (off by default)

Single-source fragility (T3): every operable detection except EP-Cat-A:T1003.001
hangs on exactly one telemetry source; EP-Cat-A:T1003.001 is telemetry-redundant
(EDR *and* Sysmon), which is also why retiring the Sysmon rule (T5) degrades only
the legacy host, not the managed one — fan-out 2, impact 1.

Prescriptive vs observed (T4): MITIGATED_BY_REF edges carry MITRE's recommended
mitigations (M-series); implemented ControlInstance names substring-match some of
them. list_mitre_recommendation_gaps() surfaces the diff. The Web App's WAF control
is implemented on the WAF App (fronting infrastructure), so it does not match on the
Web App itself — a known limitation of the instance-local match.

Usage:
    from scg.seed import load_seed
    load_seed(g)
"""

from __future__ import annotations

import logging

from scg.graph import SCG

_log = logging.getLogger(__name__)


def load_seed(g: SCG) -> None:
    _log.info("load_seed start")
    # ------------------------------------------------------------------
    # Apps — coverage-equivalence classes (see module docstring)
    # ------------------------------------------------------------------
    # Endpoint categories (a fleet abstracted by telemetry/control posture)
    g.upsert_app("app:ep-cat-a", "Endpoint Cat A (Managed)",  "edr@corp.example",     "prod", "internal")
    g.upsert_app("app:ep-cat-b", "Endpoint Cat B (Legacy)",   "edr@corp.example",     "prod", "internal")
    # Named platforms (each vendor is its own App)
    g.upsert_app("app:ad",       "Active Directory",          "adteam@corp.example",  "prod", "internal")
    g.upsert_app("app:entra",    "Microsoft Entra ID",        "cloudsec@corp.example","prod", "internet")
    g.upsert_app("app:aws",      "AWS",                       "cloudsec@corp.example","prod", "internet")
    g.upsert_app("app:gcp",      "GCP",                       "cloudsec@corp.example","prod", "internet")
    g.upsert_app("app:webapp",   "Merchant Dashboard",        "appsec@corp.example",  "prod", "internet")
    # Security-control product (a tool that implements a control + emits telemetry)
    g.upsert_app("app:waf",      "Web Application Firewall",  "appsec@corp.example",  "prod", "internet")

    # ------------------------------------------------------------------
    # TTPs (MITRE ATT&CK — sub-techniques where the real detection lives)
    # ------------------------------------------------------------------
    g.upsert_ttp("ttp:T1566.002", name="Phishing: Spearphishing Link",
                 description="Adversaries send a malicious link to gain execution on an endpoint.",
                 mitre_id="T1566.002", is_subtechnique=True)
    g.upsert_ttp("ttp:T1003.001", name="OS Credential Dumping: LSASS Memory",
                 description="Adversaries dump credential material from LSASS process memory.",
                 mitre_id="T1003.001", is_subtechnique=True)
    g.upsert_ttp("ttp:T1003.006", name="OS Credential Dumping: DCSync",
                 description="Adversaries abuse directory replication to pull credential material from a DC.",
                 mitre_id="T1003.006", is_subtechnique=True)
    g.upsert_ttp("ttp:T1078.004", name="Valid Accounts: Cloud Accounts",
                 description="Adversaries authenticate with valid cloud credentials.",
                 mitre_id="T1078.004", is_subtechnique=True)
    g.upsert_ttp("ttp:T1621", name="Multi-Factor Authentication Request Generation",
                 description="Adversaries flood a user with MFA prompts (push fatigue) to gain approval.",
                 mitre_id="T1621")
    g.upsert_ttp("ttp:T1580", name="Cloud Infrastructure Discovery",
                 description="Adversaries enumerate cloud infrastructure via the provider API.",
                 mitre_id="T1580")
    g.upsert_ttp("ttp:T1530", name="Data from Cloud Storage",
                 description="Adversaries access data objects from cloud storage.",
                 mitre_id="T1530")
    g.upsert_ttp("ttp:T1190", name="Exploit Public-Facing Application",
                 description="Adversaries exploit an internet-facing application to gain access.",
                 mitre_id="T1190")

    # ------------------------------------------------------------------
    # ATT&CK overlay — recommended mitigations (prescriptive layer, T4)
    # ------------------------------------------------------------------
    g.upsert_mitigation("mit:M1017", "M1017", "User Training")
    g.upsert_mitigation("mit:M1021", "M1021", "Restrict Web-Based Content")
    g.upsert_mitigation("mit:M1043", "M1043", "Credential Access Protection")
    g.upsert_mitigation("mit:M1028", "M1028", "Operating System Configuration")
    g.upsert_mitigation("mit:M1015", "M1015", "Active Directory Configuration")
    g.upsert_mitigation("mit:M1032", "M1032", "Multi-factor Authentication")
    g.upsert_mitigation("mit:M1026", "M1026", "Privileged Account Management")
    g.upsert_mitigation("mit:M1018", "M1018", "User Account Management")
    g.upsert_mitigation("mit:M1057", "M1057", "Data Loss Prevention")
    g.upsert_mitigation("mit:M1041", "M1041", "Encrypt Sensitive Information")
    g.upsert_mitigation("mit:M1050", "M1050", "Exploit Protection")
    g.upsert_mitigation("mit:M1030", "M1030", "Network Segmentation")

    # ------------------------------------------------------------------
    # Telemetry (environment data sources). Two exist but are NOT produced by
    # any app — the "data path does not exist" behind false coverage.
    # ------------------------------------------------------------------
    g.upsert_telemetry("tel:edr", "EDR Process/API Telemetry", "CrowdStrike Falcon",
                       owner="edr@corp.example", retention_days=180, last_verified="2026-06-20")
    g.upsert_telemetry("tel:sysmon", "Sysmon Operational (EID 1/10)", "Sysmon",
                       owner="edr@corp.example", retention_days=90, last_verified="2026-06-20")
    g.upsert_telemetry("tel:winlog", "Windows Security Log", "Windows Event Log",
                       owner="edr@corp.example", retention_days=90, last_verified="2026-06-18")
    g.upsert_telemetry("tel:dc-winsec", "DC Security Log (4662/4768)", "Windows Event Log",
                       owner="adteam@corp.example", retention_days=180, last_verified="2026-06-19")
    g.upsert_telemetry("tel:ds-repl", "AD Directory Replication Monitoring", "Windows Event Log",
                       owner="adteam@corp.example", retention_days=180, last_verified="2026-06-19")
    g.upsert_telemetry("tel:entra-signin", "Entra Sign-in & Audit Logs", "Microsoft Entra",
                       owner="cloudsec@corp.example", retention_days=90, last_verified="2026-06-21")
    g.upsert_telemetry("tel:aws-ct-mgmt", "CloudTrail Management Events", "AWS CloudTrail",
                       owner="cloudsec@corp.example", retention_days=90, last_verified="2026-06-21")
    # Exists in the catalog / expected by a detection, but NOT enabled on the account:
    g.upsert_telemetry("tel:aws-ct-data", "CloudTrail S3 Data Events", "AWS CloudTrail",
                       owner="cloudsec@corp.example", retention_days=90, last_verified="2026-06-21")
    g.upsert_telemetry("tel:gcp-audit", "GCP Admin Activity Audit Logs", "Google Cloud",
                       owner="cloudsec@corp.example", retention_days=90, last_verified="2026-06-21")
    # Off by default on GCP — the parallel to the AWS data-events gap:
    g.upsert_telemetry("tel:gcp-dataaccess", "GCP Data Access Audit Logs", "Google Cloud",
                       owner="cloudsec@corp.example", retention_days=90, last_verified="2026-06-21")
    g.upsert_telemetry("tel:webapp-log", "Application Access/Audit Logs", "Merchant Dashboard",
                       owner="appsec@corp.example", retention_days=90, last_verified="2026-06-21")
    g.upsert_telemetry("tel:waf-log", "WAF Request/Block Logs", "Web Application Firewall",
                       owner="appsec@corp.example", retention_days=90, last_verified="2026-06-21")

    # ------------------------------------------------------------------
    # Detections (each keyed to a specific telemetry via POWERS)
    # ------------------------------------------------------------------
    g.upsert_detection("det:phish-exec", "Phishing Link Execution", "EDR",
                       owner="soc@corp.example", confidence=0.70, telemetry_sources=["EDR Process/API Telemetry"])
    g.upsert_detection("det:edr-cred", "Credential Theft (EDR)", "EDR",
                       owner="soc@corp.example", confidence=0.80, telemetry_sources=["EDR Process/API Telemetry"])
    g.upsert_detection("det:sysmon-lsass", "LSASS Access (Sysmon EID 10)", "rule",
                       owner="soc@corp.example", confidence=0.85, telemetry_sources=["Sysmon Operational (EID 1/10)"])
    g.upsert_detection("det:dcsync-repl", "DCSync via Directory Replication", "rule",
                       owner="soc@corp.example", confidence=0.80, telemetry_sources=["AD Directory Replication Monitoring"])
    g.upsert_detection("det:entra-travel", "Impossible-Travel Sign-in", "ML",
                       owner="soc@corp.example", confidence=0.75, telemetry_sources=["Entra Sign-in & Audit Logs"])
    g.upsert_detection("det:entra-mfa-fatigue", "MFA Push Fatigue", "rule",
                       owner="soc@corp.example", confidence=0.70, telemetry_sources=["Entra Sign-in & Audit Logs"])
    g.upsert_detection("det:aws-assumerole", "Anomalous AssumeRole", "rule",
                       owner="soc@corp.example", confidence=0.75, telemetry_sources=["CloudTrail Management Events"])
    g.upsert_detection("det:aws-ct-discovery", "Cloud Infrastructure Enumeration", "rule",
                       owner="soc@corp.example", confidence=0.65, telemetry_sources=["CloudTrail Management Events"])
    g.upsert_detection("det:s3-mass-get", "S3 Mass Object Download", "rule",
                       owner="soc@corp.example", confidence=0.70, telemetry_sources=["CloudTrail S3 Data Events"])
    g.upsert_detection("det:gcs-exfil", "GCS Bulk Egress", "rule",
                       owner="soc@corp.example", confidence=0.70, telemetry_sources=["GCP Data Access Audit Logs"])
    g.upsert_detection("det:webapp-exploit", "Web Exploit Attempt", "rule",
                       owner="soc@corp.example", confidence=0.70, telemetry_sources=["Application Access/Audit Logs"])

    # ------------------------------------------------------------------
    # Controls (catalog) — names chosen to (substring-)match some mitigations
    # ------------------------------------------------------------------
    g.upsert_control("ctrl:safe-links",  "Restrict Web-Based Content",   "preventive", owner="appsec@corp.example",  effectiveness=0.7)
    g.upsert_control("ctrl:cred-guard",  "Credential Access Protection", "preventive", owner="edr@corp.example",     effectiveness=0.8)
    g.upsert_control("ctrl:entra-ca",    "Multi-factor Authentication",  "preventive", owner="cloudsec@corp.example", effectiveness=0.9)
    g.upsert_control("ctrl:aws-pim",     "Privileged Account Management","preventive", owner="cloudsec@corp.example", effectiveness=0.7)
    g.upsert_control("ctrl:s3-dlp",      "Data Loss Prevention",         "detective",  owner="cloudsec@corp.example", effectiveness=0.6)
    g.upsert_control("ctrl:s3-bpa",      "S3 Block Public Access",       "preventive", owner="cloudsec@corp.example", effectiveness=0.5)
    g.upsert_control("ctrl:waf-rules",   "Exploit Protection",           "preventive", owner="appsec@corp.example",  effectiveness=0.75)

    # ------------------------------------------------------------------
    # ControlInstances — concrete (App, Control) implementations
    # ------------------------------------------------------------------
    ci_safe_links = g.upsert_control_instance("app:ep-cat-a", "ctrl:safe-links", owner="appsec@corp.example",  effectiveness=0.7)
    ci_cred_guard = g.upsert_control_instance("app:ep-cat-a", "ctrl:cred-guard", owner="edr@corp.example",     effectiveness=0.8)
    ci_entra_ca   = g.upsert_control_instance("app:entra",    "ctrl:entra-ca",   owner="cloudsec@corp.example", effectiveness=0.9)
    ci_aws_pim    = g.upsert_control_instance("app:aws",      "ctrl:aws-pim",    owner="cloudsec@corp.example", effectiveness=0.7)
    ci_s3_dlp     = g.upsert_control_instance("app:aws",      "ctrl:s3-dlp",     owner="cloudsec@corp.example", effectiveness=0.6)
    ci_s3_bpa     = g.upsert_control_instance("app:aws",      "ctrl:s3-bpa",     owner="cloudsec@corp.example", effectiveness=0.5)
    # The WAF control is implemented on the WAF app (fronting infrastructure) and
    # mitigates the Web App's exploit instance — see T4 fronting note in the docstring.
    ci_waf_rules  = g.upsert_control_instance("app:waf",      "ctrl:waf-rules",  owner="appsec@corp.example",  effectiveness=0.75)

    # ------------------------------------------------------------------
    # ThreatInstances (relevant (app, ttp) pairs only — not a full grid)
    # ------------------------------------------------------------------
    ti_epa_phish = g.upsert_threat_instance("app:ep-cat-a", "ttp:T1566.002", likelihood=0.6, impact=0.6, priority=4)
    ti_epb_phish = g.upsert_threat_instance("app:ep-cat-b", "ttp:T1566.002", likelihood=0.5, impact=0.6, priority=3)
    ti_epa_lsass = g.upsert_threat_instance("app:ep-cat-a", "ttp:T1003.001", likelihood=0.5, impact=0.8, priority=4)
    ti_epb_lsass = g.upsert_threat_instance("app:ep-cat-b", "ttp:T1003.001", likelihood=0.4, impact=0.8, priority=4)
    ti_ad_dcsync = g.upsert_threat_instance("app:ad",       "ttp:T1003.006", likelihood=0.3, impact=0.95, priority=5)
    ti_entra_va  = g.upsert_threat_instance("app:entra",    "ttp:T1078.004", likelihood=0.6, impact=0.85, priority=5)
    ti_entra_mfa = g.upsert_threat_instance("app:entra",    "ttp:T1621",     likelihood=0.5, impact=0.6, priority=3)
    ti_aws_va    = g.upsert_threat_instance("app:aws",      "ttp:T1078.004", likelihood=0.5, impact=0.9, priority=5)
    ti_aws_disc  = g.upsert_threat_instance("app:aws",      "ttp:T1580",     likelihood=0.4, impact=0.5, priority=2)
    ti_aws_data  = g.upsert_threat_instance("app:aws",      "ttp:T1530",     likelihood=0.4, impact=0.9, priority=4)
    ti_gcp_va    = g.upsert_threat_instance("app:gcp",      "ttp:T1078.004", likelihood=0.4, impact=0.8, priority=4)
    ti_gcp_data  = g.upsert_threat_instance("app:gcp",      "ttp:T1530",     likelihood=0.3, impact=0.8, priority=3)
    ti_webapp    = g.upsert_threat_instance("app:webapp",   "ttp:T1190",     likelihood=0.6, impact=0.8, priority=5)

    # ------------------------------------------------------------------
    # Structural edges: HAS_TI and DESCRIBES
    # ------------------------------------------------------------------
    for ti_id, app_id, ttp_id in [
        (ti_epa_phish, "app:ep-cat-a", "ttp:T1566.002"),
        (ti_epb_phish, "app:ep-cat-b", "ttp:T1566.002"),
        (ti_epa_lsass, "app:ep-cat-a", "ttp:T1003.001"),
        (ti_epb_lsass, "app:ep-cat-b", "ttp:T1003.001"),
        (ti_ad_dcsync, "app:ad",       "ttp:T1003.006"),
        (ti_entra_va,  "app:entra",    "ttp:T1078.004"),
        (ti_entra_mfa, "app:entra",    "ttp:T1621"),
        (ti_aws_va,    "app:aws",      "ttp:T1078.004"),
        (ti_aws_disc,  "app:aws",      "ttp:T1580"),
        (ti_aws_data,  "app:aws",      "ttp:T1530"),
        (ti_gcp_va,    "app:gcp",      "ttp:T1078.004"),
        (ti_gcp_data,  "app:gcp",      "ttp:T1530"),
        (ti_webapp,    "app:webapp",   "ttp:T1190"),
    ]:
        g.add_edge("HAS_TI",    app_id, ti_id)
        g.add_edge("DESCRIBES", ttp_id, ti_id)

    # ------------------------------------------------------------------
    # App → Telemetry (PRODUCES). Note the two deliberately-absent producers:
    # AWS does not produce CloudTrail S3 *data* events; GCP does not produce
    # Data Access logs — both drive false coverage below.
    # ------------------------------------------------------------------
    g.add_edge("PRODUCES", "app:ep-cat-a", "tel:edr")
    g.add_edge("PRODUCES", "app:ep-cat-a", "tel:sysmon")
    g.add_edge("PRODUCES", "app:ep-cat-a", "tel:winlog")
    g.add_edge("PRODUCES", "app:ep-cat-b", "tel:winlog")     # legacy host: Windows Security only
    g.add_edge("PRODUCES", "app:ad",       "tel:ds-repl")
    g.add_edge("PRODUCES", "app:ad",       "tel:dc-winsec")
    g.add_edge("PRODUCES", "app:entra",    "tel:entra-signin")
    g.add_edge("PRODUCES", "app:aws",      "tel:aws-ct-mgmt")
    g.add_edge("PRODUCES", "app:gcp",      "tel:gcp-audit")
    g.add_edge("PRODUCES", "app:webapp",   "tel:webapp-log")
    g.add_edge("PRODUCES", "app:waf",      "tel:waf-log")

    # ------------------------------------------------------------------
    # Telemetry → Detection (POWERS)
    # ------------------------------------------------------------------
    g.add_edge("POWERS", "tel:edr",           "det:phish-exec")
    g.add_edge("POWERS", "tel:edr",           "det:edr-cred")
    g.add_edge("POWERS", "tel:sysmon",        "det:sysmon-lsass")
    g.add_edge("POWERS", "tel:ds-repl",       "det:dcsync-repl")
    g.add_edge("POWERS", "tel:entra-signin",  "det:entra-travel")
    g.add_edge("POWERS", "tel:entra-signin",  "det:entra-mfa-fatigue")
    g.add_edge("POWERS", "tel:aws-ct-mgmt",   "det:aws-assumerole")
    g.add_edge("POWERS", "tel:aws-ct-mgmt",   "det:aws-ct-discovery")
    g.add_edge("POWERS", "tel:aws-ct-data",   "det:s3-mass-get")     # data events not produced → false coverage
    g.add_edge("POWERS", "tel:gcp-dataaccess", "det:gcs-exfil")      # data access off → false coverage
    g.add_edge("POWERS", "tel:webapp-log",    "det:webapp-exploit")

    # ------------------------------------------------------------------
    # ThreatInstance → Detection (DETECTED_BY)
    # ------------------------------------------------------------------
    g.add_edge("DETECTED_BY", ti_epa_phish, "det:phish-exec")     # operable (EP-A produces EDR)
    g.add_edge("DETECTED_BY", ti_epa_lsass, "det:edr-cred")       # operable — redundant path #1
    g.add_edge("DETECTED_BY", ti_epa_lsass, "det:sysmon-lsass")   # operable — redundant path #2
    g.add_edge("DETECTED_BY", ti_epb_lsass, "det:sysmon-lsass")   # FALSE: EP-B runs no Sysmon
    g.add_edge("DETECTED_BY", ti_ad_dcsync, "det:dcsync-repl")    # operable (AD produces ds-repl)
    g.add_edge("DETECTED_BY", ti_entra_va,  "det:entra-travel")   # operable
    g.add_edge("DETECTED_BY", ti_entra_mfa, "det:entra-mfa-fatigue")
    g.add_edge("DETECTED_BY", ti_aws_va,    "det:aws-assumerole") # operable
    g.add_edge("DETECTED_BY", ti_aws_disc,  "det:aws-ct-discovery")
    g.add_edge("DETECTED_BY", ti_aws_data,  "det:s3-mass-get")    # FALSE: S3 data events not enabled
    g.add_edge("DETECTED_BY", ti_gcp_data,  "det:gcs-exfil")      # FALSE: GCP data access off
    g.add_edge("DETECTED_BY", ti_webapp,    "det:webapp-exploit") # operable
    # (EP-Cat-B:T1566.002 and GCP:T1078.004 have NO detection — true gaps, for T1)

    # ------------------------------------------------------------------
    # HAS_CI: App → ControlInstance
    # ------------------------------------------------------------------
    g.add_edge("HAS_CI", "app:ep-cat-a", ci_safe_links)
    g.add_edge("HAS_CI", "app:ep-cat-a", ci_cred_guard)
    g.add_edge("HAS_CI", "app:entra",    ci_entra_ca)
    g.add_edge("HAS_CI", "app:aws",      ci_aws_pim)
    g.add_edge("HAS_CI", "app:aws",      ci_s3_dlp)
    g.add_edge("HAS_CI", "app:aws",      ci_s3_bpa)
    g.add_edge("HAS_CI", "app:waf",      ci_waf_rules)

    # ------------------------------------------------------------------
    # IMPLEMENTED_BY: Control catalog → ControlInstance
    # ------------------------------------------------------------------
    g.add_edge("IMPLEMENTED_BY", "ctrl:safe-links", ci_safe_links)
    g.add_edge("IMPLEMENTED_BY", "ctrl:cred-guard", ci_cred_guard)
    g.add_edge("IMPLEMENTED_BY", "ctrl:entra-ca",   ci_entra_ca)
    g.add_edge("IMPLEMENTED_BY", "ctrl:aws-pim",    ci_aws_pim)
    g.add_edge("IMPLEMENTED_BY", "ctrl:s3-dlp",     ci_s3_dlp)
    g.add_edge("IMPLEMENTED_BY", "ctrl:s3-bpa",     ci_s3_bpa)
    g.add_edge("IMPLEMENTED_BY", "ctrl:waf-rules",  ci_waf_rules)

    # ------------------------------------------------------------------
    # MITIGATED_BY: ThreatInstance → ControlInstance (what we actually implement)
    # ------------------------------------------------------------------
    g.add_edge("MITIGATED_BY", ti_epa_phish, ci_safe_links)
    g.add_edge("MITIGATED_BY", ti_epa_lsass, ci_cred_guard)
    g.add_edge("MITIGATED_BY", ti_entra_va,  ci_entra_ca)
    g.add_edge("MITIGATED_BY", ti_entra_mfa, ci_entra_ca)
    g.add_edge("MITIGATED_BY", ti_aws_va,    ci_aws_pim)
    g.add_edge("MITIGATED_BY", ti_aws_data,  ci_s3_dlp)
    g.add_edge("MITIGATED_BY", ti_aws_data,  ci_s3_bpa)
    g.add_edge("MITIGATED_BY", ti_webapp,    ci_waf_rules)

    # ------------------------------------------------------------------
    # MITIGATED_BY_REF: TTP → Mitigation (what MITRE recommends — the diff vs
    # MITIGATED_BY is the T4 headline, via list_mitre_recommendation_gaps()).
    # ------------------------------------------------------------------
    for ttp_id, mit_id in [
        ("ttp:T1566.002", "mit:M1017"), ("ttp:T1566.002", "mit:M1021"),
        ("ttp:T1003.001", "mit:M1043"), ("ttp:T1003.001", "mit:M1028"),
        ("ttp:T1003.006", "mit:M1015"),
        ("ttp:T1078.004", "mit:M1032"), ("ttp:T1078.004", "mit:M1026"),
        ("ttp:T1621",     "mit:M1032"),
        ("ttp:T1580",     "mit:M1018"),
        ("ttp:T1530",     "mit:M1057"), ("ttp:T1530", "mit:M1041"),
        ("ttp:T1190",     "mit:M1050"), ("ttp:T1190", "mit:M1030"),
    ]:
        g.add_edge("MITIGATED_BY_REF", ttp_id, mit_id)

    # ------------------------------------------------------------------
    # Engineer override (§3.2): S3 Block Public Access is preventive, so AWS ·
    # T1530 computes as covered — but it does not stop an authenticated
    # principal from mass-downloading objects, so the effective status is
    # partial, with the override's identity and reason on record.
    # ------------------------------------------------------------------
    g.set_status_override(
        ti_aws_data, "partial", engineer="cloudsec@corp.example",
        reason="S3 Block Public Access does not prevent an authenticated principal "
               "from mass-downloading objects (T1530)",
    )

    # Refresh planner statistics after the bulk load so the coverage analytics
    # pick the composite edge indexes (see SCG.analyze).
    g.analyze()
    _log.info("load_seed done summary=%s", g.graph_summary())


def main(db_path: str = "scg.db") -> None:
    with SCG(db_path) as g:
        load_seed(g)
    _log.info("seed loaded db_path=%s", db_path)
    print(f"Seed data loaded into {db_path!r}.")


if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "scg.db")
