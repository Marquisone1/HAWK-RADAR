# HAWK RADAR

![Status](https://img.shields.io/badge/status-experimental-orange)
![Stack](https://img.shields.io/badge/stack-Flask%20%7C%20SQLite%20%7C%20Docker-blue)
![Purpose](https://img.shields.io/badge/purpose-learning%20%2F%20demo-yellow)
![Enterprise Ready](https://img.shields.io/badge/enterprise-ready-red)

A lightweight RSS-based threat intelligence dashboard built with Flask, SQLite, and Docker.

## Production Warning

This project is vibe coded and intended for experimentation, learning, and internal demo use.

It is not designed, reviewed, or hardened for enterprise production environments.
Do not treat this repository as production-ready security tooling.

## Important Disclaimer

This project is vibe coded and intended for experimentation, learning, and internal demo use.

It is not designed, reviewed, or hardened for enterprise production environments.
Use at your own risk.

## What It Does

- Aggregates cybersecurity RSS feeds
- Classifies items by severity
- Extracts basic indicators (IP, domain, CVE, hash)
- Supports filtering, starring, unread tracking, and related records

## Quick Start

1. Build and run:
   - docker compose up --build -d
2. Open:
   - http://127.0.0.1:3001

## Security Note

If you deploy this beyond local testing, perform a full security review first (auth hardening, dependency auditing, secret handling, logging policy, and infrastructure controls).
