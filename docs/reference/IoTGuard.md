# AI-Assisted IoT Security Compliance & Risk Assessment Platform — NCA-Aligned

> KAUST ACADEMY — CYBERSECURITY SPECIALIZATION
>
> **NCA-ALIGNED · IoT-SPM**

Source: https://mohamadtalagi.github.io/IoTGuard/

---

## Project Premise

A plug-and-play IoT Security Posture Management (IoT-SPM) solution built for organizations in Saudi Arabia. It automatically discovers IoT devices on a network, fingerprints them, evaluates their compliance against National Cybersecurity Authority (NCA) controls, assesses security posture with vulnerability intelligence and dynamic risk scoring, and generates AI-powered remediation blueprints.

Unlike traditional compliance auditors that only report policy violations, the platform runs an end-to-end workflow — from asset discovery to actionable remediation — so organizations can continuously improve their IoT security posture.

---

## Pipeline Flow

1. Platform Deployment
2. Network Discovery
3. Device Fingerprinting
4. NCA Compliance
5. Vulnerability Intel
6. Dynamic Risk
7. AI Security Blueprint
8. AI Exec Summary
9. Security Dashboard
10. Continuous Monitoring

**10 STAGES**

---

## Stage 01 — Platform Deployment & Initialization

**PURPOSE**

Initialize the platform and provide a plug-and-play deployment experience with minimal configuration. The platform starts all required services and prepares the system for network assessment.

**DEPENDS ON**

None — entry point of the pipeline.

**INPUT**

- Docker containers
- Configuration files
- Network connection

**PROCESS**

- Start backend services
- Start frontend application
- Initialize database
- Verify network connectivity
- Load compliance rules
- Initialize AI services

**OUTPUT**

A fully operational platform accessible through a web interface.

**TECHNOLOGIES**

Docker · Docker Compose · FastAPI · Flutter Web · PostgreSQL · Nginx (optional)

---

## Stage 02 — Network Discovery

**PURPOSE**

Discover every reachable IoT device connected to the local network. This stage establishes the asset inventory that every subsequent stage depends upon.

**DEPENDS ON**

Stage 1 — the platform must already be operational before scanning can begin.

**PROCESS**

- Detect local subnet
- Perform host discovery
- Identify active devices
- Detect open ports
- Store discovered devices

**OUTPUT**

Network inventory — e.g. security cameras, printers, routers, smart TVs, IoT sensors.

**TECHNOLOGIES**

Nmap · python-nmap · Scapy · ARP Scanning · SSDP · mDNS

---

## Stage 03 — Device Fingerprinting

**PURPOSE**

Identify exactly what each discovered device is. Instead of identifying only IP addresses, this stage determines the characteristics of each asset.

**DEPENDS ON**

Stage 2 — requires the discovered device inventory.

**PROCESS**

- Identify manufacturer
- Identify device model
- Identify firmware version
- Detect operating system
- Detect running services
- Detect supported protocols
- Retrieve hardware information when available

**OUTPUT**

Complete device profile — vendor, model, firmware, services, ports, device type.

**TECHNOLOGIES**

Nmap Service Detection · Banner Grabbing · SNMP · ONVIF (IP Cameras) · MAC Vendor Lookup Database

---

## Stage 04 — NCA Compliance Assessment

**PURPOSE**

Evaluate every identified device against cybersecurity controls derived from the Saudi National Cybersecurity Authority (NCA). This stage transforms raw device information into measurable compliance.

**DEPENDS ON**

Stage 3 — requires accurate device information before compliance evaluation can occur.

**PROCESS**

- Authentication configuration
- Password policy
- Remote management protocols
- Encryption configuration
- Logging configuration
- Firmware policy
- Secure configuration
- Network exposure

Each finding is mapped to a corresponding NCA control.

**OUTPUT**

Compliance score, violated controls, compliance report.

**TECHNOLOGIES**

Python Rule Engine · YAML/JSON Rule Definitions · NCA Cybersecurity Controls Framework

---

## Stage 05 — Vulnerability Intelligence

**PURPOSE**

Determine whether identified devices are affected by publicly disclosed vulnerabilities. This stage enriches compliance findings with real-world threat intelligence.

**DEPENDS ON**

Stages 3 and 4 — requires accurate device fingerprinting and compliance information.

**PROCESS**

- Compare vendor, model, and firmware version against CVE Database, NVD, and CISA Known Exploited Vulnerabilities
- Retrieve CVSS score, severity, and exploit availability

**OUTPUT**

Every device receives vulnerability information.

**TECHNOLOGIES**

National Vulnerability Database (NVD) · CVE Database · CVSS · CISA KEV · EPSS (optional)

---

## Stage 06 — Dynamic Risk Assessment

**PURPOSE**

Combine technical findings into a unified security risk score. Instead of isolated findings, administrators receive prioritized security risks.

**DEPENDS ON**

Stages 4 and 5 — uses both compliance violations and vulnerability intelligence.

**PROCESS**

- Compliance score
- CVSS
- Exploit availability
- Device criticality
- Internet exposure
- Number of violations
- Insecure services

Analyzed together to calculate overall device risk.

**OUTPUT**

Every device receives a risk score, risk category, and organizational priority.

**TECHNOLOGIES**

Python · Risk Scoring Algorithm · Pandas (optional)

---

## Stage 07 — AI Security Blueprint & Remediation Engine

**PURPOSE**

Transform security findings into structured remediation plans. Instead of simply identifying problems, the platform generates implementation blueprints that guide administrators through mitigation.

**DEPENDS ON**

Stages 4, 5 and 6 — requires compliance violations, vulnerabilities, and risk assessment.

**PROCESS**

- Analyze all findings
- Generate problem description
- Generate security impact
- Map to related NCA control
- Generate step-by-step remediation
- Estimate expected risk reduction
- Assign implementation priority
- Generate overall remediation roadmap

**OUTPUT**

AI-generated Security Blueprint, e.g. Priority 1: Update Firmware → Priority 2: Disable Telnet → Priority 3: Replace Default Credentials → Priority 4: Enable HTTPS.

**TECHNOLOGIES**

Large Language Model (LLM) · Prompt Engineering · OpenAI API / Azure OpenAI / Local LLM · Retrieval-Augmented Generation (optional)

---

## Stage 08 — AI Executive Summary

**PURPOSE**

Summarize the overall security posture of the organization for both technical and non-technical stakeholders.

**DEPENDS ON**

Stages 4 through 7 — uses compliance, vulnerabilities, risk, and the security blueprint.

**PROCESS**

- Overall security posture
- Highest-risk devices
- Most significant compliance gaps
- Priority recommendations
- Estimated improvement after remediation

**OUTPUT**

Executive summary report.

**TECHNOLOGIES**

LLM · Prompt Templates

---

## Stage 09 — Security Dashboard

**PURPOSE**

Present all collected information through an intuitive interface that enables administrators to monitor their IoT environment.

**DEPENDS ON**

All previous stages — the dashboard aggregates the output of every module.

**PROCESS**

- Device inventory
- Compliance score
- Risk distribution
- Vulnerabilities
- Security blueprints
- Executive summary
- Historical trends

Provides filtering, searching, and reporting capabilities.

**OUTPUT**

Interactive web application.

**TECHNOLOGIES**

Flutter Web · REST API · FastAPI · Charts (fl_chart) · Data Tables

---

## Stage 10 — Continuous Monitoring & Historical Analysis

**PURPOSE**

Maintain continuous visibility into the organization's IoT security posture by periodically reassessing the environment. This transforms the platform from a one-time assessment tool into a continuous monitoring solution.

**DEPENDS ON**

All previous stages — each scheduled scan repeats the complete assessment workflow.

**PROCESS**

- Perform scheduled scans
- Detect new devices
- Detect firmware changes
- Detect newly published vulnerabilities
- Detect compliance improvements
- Detect compliance regressions
- Track historical metrics
- Generate alerts when security posture changes

**OUTPUT**

Continuous monitoring dashboard, historical compliance trends, historical risk trends, alert notifications.

**TECHNOLOGIES**

PostgreSQL · APScheduler / Celery · FastAPI Background Tasks · Email Notification Service (optional)

---

## Complete System Workflow

1. Platform Deployment
2. Network Discovery
3. Device Fingerprinting
4. NCA Compliance Assessment
5. Vulnerability Intelligence
6. Dynamic Risk Assessment
7. AI Security Blueprint
8. AI Executive Summary
9. Security Dashboard
10. Continuous Monitoring

Each stage builds upon the output of the previous stage, progressively transforming raw network data into actionable cybersecurity intelligence — a comprehensive, AI-assisted IoT Security Posture Management platform tailored to Saudi Arabia's NCA cybersecurity framework.
