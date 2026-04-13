# HAWK RADAR

![Status](https://img.shields.io/badge/status-experimental-orange)
![Stack](https://img.shields.io/badge/stack-Flask%20%7C%20SQLite%20%7C%20Docker-blue)
![Purpose](https://img.shields.io/badge/purpose-learning%20%2F%20demo-yellow)

A lightweight RSS-based threat intelligence dashboard built with Flask, SQLite, and Docker.

## Release 1.1

This release expands HAWK RADAR from a basic feed reader into a more usable analyst dashboard with watchlists, cleaner IOC handling, stronger related-item logic, and better analytics.

## Production Warning

This project is vibe coded and intended for experimentation, learning, and internal demo use.

It is not designed, reviewed, or hardened for enterprise production environments.
Do not treat this repository as production-ready security tooling.

## What It Does

- Aggregates cybersecurity RSS feeds
- Classifies items by severity
- Extracts basic indicators (IP, domain, CVE, hash)
- Supports filtering, starring, watchlists, and related records

## New In 1.1

- Custom watchlists with tracked terms, match counts, and highlighted items
- Dedicated watchlist page with clickable matched items and term-based filtering
- Watchlist filter on the main radar page
- CVE-aware duplicate clustering to reduce repeated noise across sources
- CVE frequency analytics chart for frequently referenced vulnerabilities
- Improved severity fallback scoring to reduce `unknown` items
- Stricter related-record matching based on CVEs, IOCs, and strong threat tags
- Exact published date/time display on radar cards
- Cleaner IOC extraction with reduced false positives from provider and source domains
- Expanded feed coverage including Talos, CrowdStrike, Darknet Diaries, SANS ISC, and DFN-CERT fixes

## Planned Next

- More flexible analyst workflows and filtering
- Additional enrichment and context around tracked items
- Further tuning for IOC quality and duplicate reduction
- Better export/report and triage-oriented views

## Quick Start

1. Build and run:
   - docker compose up --build -d
2. Open:
   - http://127.0.0.1:3001

## IOC Refresh Note

IOC extraction rules may change over time as false positives are tuned out.

If you are using an existing database and update to a version with new IOC extraction logic, you may want to reprocess stored items so analytics and filters reflect the newer rules.

Typical example: benign provider/source domains may have been extracted by older rules and later removed by newer ones.

The application will use the latest rules for newly ingested items automatically, but existing rows in the database keep their stored IOC data until you re-extract or rebuild that data.

## Security Note

If you deploy this beyond local testing, perform a full security review first (auth hardening, dependency auditing, secret handling, logging policy, and infrastructure controls).
