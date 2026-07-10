
# Unisoc T606/T616 Supply Chain Detection Suite  
## Technical Release for Defensive Validation and Incident Response

**Publication Date:** July 10, 2026  
**Author:** lexs201992-gif (Independent Security Research, LATAM Division)  
**Version:** 1.0.0  
**Severity Classification:** CRITICAL (Defensive Context)  
**TLP:** WHITE (Public Distribution)

---

## 1. Purpose and Scope

This repository provides a defensive **YARA detection suite** intended to support:
- Incident response triage
- Firmware and system image analysis
- Enterprise/mobile fleet risk assessment
- Cross-team intelligence sharing for suspected supply chain abuse

The current research focus is on potential compromise indicators associated with selected **Unisoc T606/T616** device ecosystems and vendor overlay abuse patterns.

> **Important:** These signatures are intended for **detection and validation**, not attribution by themselves.

---

## 2. Operational Context (Defensive Framing)

The rules are designed to identify suspicious artifacts potentially consistent with:
- Runtime Resource Overlay (RRO) abuse
- Vendor partition persistence mechanisms
- Security policy degradation/bypass attempts
- Covert communication artifacts (including WireGuard/MACsec-like traces)

Findings should be interpreted in combination with:
1. Firmware provenance verification
2. Certificate chain analysis
3. Device telemetry and network evidence
4. Reproducible forensic workflows

---

## 3. Rule Set Summary

### 3.1 `SupplyChain_Overlay_Abuse_Unisoc` (Addendum #81)
**Objective:** Detect suspicious Android overlay abuse behavior.  
**Primary Indicators:**
- `android.unisoc.*` namespace patterns
- `/vendor/overlay` and related overlay paths
- Build anomalies (e.g., auto-generated overlay + injection-like artifacts)

**Recommended Use:** Persistence and post-reset artifact validation.

---

### 3.2 `Unisoc_Vendor_Overlay_Backdoor_Fleet` (Addendum #82)
**Objective:** Identify hardcoded vendor/device indicators associated with suspicious reference designs.  
**Primary Indicators:**
- `cpu_T606`
- board codename `qogirl6`
- certificate anomalies referencing `CN=Longcheer`

**Recommended Use:** High-confidence enterprise fleet triage and escalation.

---

### 3.3 `Unisoc_T606_Supply_Chain_Master` (Final Assessment)
**Objective:** Correlate multi-layer indicators for incident confirmation workflows.  
**Primary Indicators:**
- Suspicious package/hash intelligence (where available)
- Exfiltration artifact strings (`wireguard`, `macsec`)
- Hardware identifiers (`ums9230`, `ums9130`)

**Recommended Use:** IR confirmation support and structured reporting.

---

## 4. Implementation Guidance

### 4.1 Incident Response / Forensic Teams
Use YARA scanning over firmware dumps, extracted partitions, and known-good baselines:

```bash
yara -r unisoc_supply_chain_rules.yar /path/to/firmware_dump/
```

**Interpretation Model**
- **Positive match:** treat as a **potential compromise indicator**, isolate asset, preserve evidence, escalate for full forensic review.
- **No match:** **not a guarantee of absence**; continue behavioral and network analysis.

---

### 4.2 Enterprise / Government (MDM, EDR, SOC)
1. Scan at minimum: `/vendor/overlay`, `/product/overlay`, `/system`
2. Correlate matches with device model, build fingerprint, and signing cert chain
3. Quarantine high-confidence detections pending forensic verification
4. Maintain longitudinal integrity checks for vendor partition drift

---

### 4.3 Network Defense (Suricata/Zeek/NDR)
Complement file-based detections with telemetry hunting for:
- QUIC/WireGuard-like flows on atypical destinations/ports
- Beacon-like timing from affected device groups
- Correlated DNS/TLS anomalies tied to suspicious devices

---

## 5. Evidence Handling and Quality Controls

To improve confidence and reduce false positives:
- Validate against a clean baseline image per model/build
- Record full hash provenance (SHA-256) for all analyzed artifacts
- Preserve chain-of-custody metadata (acquisition time, source, tool versions)
- Require multi-signal confirmation before formal escalation
- Re-test detections after vendor OTA updates and policy changes

---

## 6. Public Repositories and Related Work

- **YARA Investigation Rules (this repository):**  
  https://github.com/lexs201992-gif/Yara-investigation-rules-

- **Technical research repository:**  
  https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum

- **Citizen Protection Guide (public awareness and mitigation):**  
  https://github.com/lexs201992-gif/Citizen-Protection-Guide-Mitigating-the-Unisoc-Longcheer-Threat

---

## 7. Legal and Analytical Disclaimer

- This repository is provided for **defensive security operations** and research collaboration.
- Detection hits indicate **suspicious conditions**, not automatic legal attribution.
- Any references to actors, vendors, or campaigns should be treated as **analytical hypotheses** unless independently verified by competent authorities.
- Users are responsible for compliance with applicable laws, disclosure regimes, and internal policy.

---

## 8. Collaboration and Responsible Disclosure

Contributions are welcome for:
- Variant samples and new IOCs
- False-positive/false-negative reports
- Additional telemetry correlation rules
- Regional threat intelligence context

### Contact and Profiles
- **ORCID:** https://orcid.org/0009-0009-4336-1491
- **AttackerKB:** https://attackerkb.com/contributors/lexs201992-gif
- **LinkedIn:** https://www.linkedin.com/in/alexdelacruz92?trk=contact-info
- **VirusTotal:** https://www.virustotal.com/gui/user/Alex992
- **Email:** lexs201992@gmail.com
- **PGP:** Available upon request for encrypted communication

---

## 9. Spanish Summary / Resumen en Español

Este repositorio publica una suite de reglas YARA para validación defensiva ante posibles compromisos de cadena de suministro en ecosistemas Unisoc T606/T616.  
Las detecciones deben interpretarse en conjunto con análisis forense, telemetría de red, verificación de certificados y control de integridad de firmware.  
Un match YARA es un **indicador técnico de riesgo**, no una atribución definitiva.

Repositorios públicos relacionados:
- https://github.com/lexs201992-gif/Yara-investigation-rules-
- https://github.com/lexs201992-gif/motorola-g04s-t606-spreadtrum
- https://github.com/lexs201992-gif/Citizen-Protection-Guide-Mitigating-the-Unisoc-Longcheer-Threat

---

**Recommended citation:**  
lexs201992-gif. *Unisoc T606/T616 Supply Chain Detection Suite*. Version 1.0.0, July 2026.
