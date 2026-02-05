# API Security Posture Scanner

A comprehensive CLI tool for assessing REST, GraphQL, and gRPC API security posture based on OWASP API Security Top 10.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.7+-blue)

## 📋 Description

API Security Posture Scanner is a powerful security assessment tool designed to identify vulnerabilities and misconfigurations in REST, GraphQL, and gRPC APIs. The scanner performs automated security checks aligned with OWASP API Security Top 10 guidelines.

## ✨ Features

- **Multi-Protocol Support**: REST, GraphQL, and gRPC API scanning
- **Auto-Detection**: Automatic API type detection
- **OWASP Compliance**: Checks based on OWASP API Security Top 10 (2023)
- **Comprehensive Checks**:
  - Security headers validation
  - CORS misconfiguration
  - Authentication issues
  - Information disclosure
  - Rate limiting
  - TLS/SSL configuration
  - GraphQL-specific vulnerabilities
  - gRPC security checks
- **Multiple Output Formats**: Console, JSON, and HTML reports
- **Rich CLI Interface**: Colorful terminal output with progress indicators

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```
Optional Dependencies
grpcio and grpcio-tools for gRPC scanning
pyfiglet for enhanced banner display

📖 Usage
Basic Scan
```bash
python apisecposture.py https://api.example.com
```
REST API Scanning
```bash
# With custom headers
python apisecposture.py https://api.example.com --headers '{"X-API-Key": "secret123"}'

# With authentication
python apisecposture.py https://api.example.com --auth your_token_here

# Aggressive mode (more comprehensive checks)
python apisecposture.py https://api.example.com --aggressive --i-understand-legal-responsibilities
```
GraphQL API Scanning
```bash
# Auto-detect
python apisecposture.py https://api.example.com/graphql

# Explicit type
python apisecposture.py https://api.example.com/graphql --type graphql
```
gRPC API Scanning
```bash
python apisecposture.py grpc://api.example.com:50051 --type grpc
```
Export Results
```bash
# JSON format
python apisecposture.py https://api.example.com --output results.json

# HTML format
python apisecposture.py https://api.example.com --output report.html
```
View All Options
```bash
python apisecposture.py --help
python apisecposture.py --examples
```
⚠️ Disclaimer
This tool is provided for educational and authorized security testing purposes only. The author is not responsible for any misuse or damage caused by this tool.
