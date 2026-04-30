# FinSec — Financial Security Auditor

Security platform for AWS EC2 security group auditing and real-time threat detection.

## Part 1 — AWS Security Auditor
Scans EC2 security group inbound rules and flags dangerous misconfigurations
such as open ports to 0.0.0.0/0. Generates prioritised risk reports with HIGH,
MEDIUM, and LOW ratings — addressing PCI-DSS Requirements 1 and 11.

## Part 2 — Threat Detection API
Flask REST API implementing:
- Rate limiting — blocks IPs exceeding 10 requests per minute
- Brute force detection — blocks IP after 5 failed login attempts
- SQL injection detection — pattern matching on all inputs
- XSS detection — pattern matching on all inputs
- Security event logging — full audit trail of all security events
- Security headers — HSTS, X-Frame-Options, X-Content-Type-Options

## Tech Stack
Python, Flask, Boto3, AWS EC2

## Setup

### Part 1 — AWS Security Auditor
pip install boto3
python aws_audit/audit.py

### Part 2 — Threat Detection API
pip install -r threat_detection_api/requirements.txt
python threat_detection_api/app.py

## API Endpoints
POST /api/login              — login with brute force and injection protection
GET  /api/security/events    — view all security events logged
GET  /api/security/blocked   — view currently blocked IPs
POST /api/unblock            — unblock all IPs (testing only)

## Security Features
- Defends against 6 of OWASP Top 10 risks
- Addresses PCI-DSS Requirements 1, 10, and 11
- Functions as an application-level IPS
- Implements Defence in Depth across network and application layers

## Project Status
- Part 1 AWS Security Auditor — Complete
- Part 2 Threat Detection API — Complete
- Part 3 PCI-DSS Compliance Checker — In Progress