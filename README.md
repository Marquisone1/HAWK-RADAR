# HAWK RADAR

A lightweight RSS-based threat intelligence dashboard built with Flask, SQLite, and Docker.

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
