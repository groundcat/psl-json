# Public Suffix List Parser

A comprehensive Python tool for parsing, analyzing, and enriching the [Public Suffix List (PSL)](https://publicsuffix.org/) with additional metadata.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output Files](#output-files)
- [Understanding the PSL Format](#understanding-the-psl-format)
- [Domain Processing](#domain-processing)
- [Performance Considerations](#performance-considerations)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

## Overview

The Public Suffix List (PSL) is a crucial database maintained by the Mozilla Foundation that catalogs top-level domains (TLDs) under which internet users can directly register names. This parser downloads the PSL, processes each entry, and enhances it with additional metadata from DNS and WHOIS sources.

The script generates multiple JSON files with varying levels of detail, allowing for integration with different systems and use cases.

## Features

- **Complete PSL Processing:** Parses both ICANN and private domains with proper section handling
- **Metadata Extraction:** Extracts requestor information, contact details, and descriptions from PSL comments
- **Domain Attributes:** Identifies wildcard and negation domains based on PSL notation
- **Domain Normalization:** Normalizes private domains according to ICANN standards
- **DNS Integration:** Detects DNS errors using Cloudflare's DNS over HTTPS (DoH)
- **WHOIS Enrichment:** Enhances entries with comprehensive registry records
- **Multiple Output Formats:** Generates three different JSON files with varying levels of detail
- **Version Tracking:** Extracts and saves PSL version and commit information
- **Batch Processing:** Handles API rate limits with efficient batch processing
- **Caching:** Implements intelligent caching to avoid redundant API calls
- **Robust Error Handling:** Gracefully handles network errors and API failures

## Installation

### Prerequisites

- Python 3.7 or higher
- Required Python packages: `requests`
- An external [whois-domain-lookup](https://github.com/reg233/whois-domain-lookup) instance

### Setup

1. Clone this repository or download the script:

```bash
git clone https://github.com/yourusername/psl-parser.git
cd psl-parser
```

2. Install the required packages:

```bash
pip install requests
```

## Configuration

The script provides several configuration options that can be adjusted at the top of the file:

```python
# Configuration
psl_url = "https://publicsuffix.org/list/public_suffix_list.dat"
api_endpoint_url = "https://API_SERVER_DOMAIN/api/?domain="
api_additional_headers = {}  # Empty by default
api_timeout_seconds = 5
api_interval_seconds = 1
debug_mode = True
debug_log_enabled = True
MAX_RETRIES = 3
```

- `psl_url`: URL to download the Public Suffix List
- `api_endpoint_url`: Base URL for the WHOIS API of a [whois-domain-lookup](https://github.com/reg233/whois-domain-lookup) instance
- `api_additional_headers`: Optional headers to include in API requests
- `api_timeout_seconds`: Timeout for API requests
- `api_interval_seconds`: Delay between API requests to avoid rate limiting
- `debug_mode`: Enable verbose logging
- `debug_log_enabled`: Write logs to a file
- `MAX_RETRIES`: Number of retry attempts for failed requests

## Usage

Run the script from the command line:

```bash
python psl_parser.py
```

The script will:
1. Download the PSL
2. Extract version information
3. Parse all PSL entries
4. Normalize domains
5. Perform DNS checks
6. Retrieve WHOIS data
7. Generate multiple JSON output files

### Example Output

After running the script, you'll see progress information and a completion message:

```
2025-05-17 10:15:23 - INFO - PSL Parser started
2025-05-17 10:15:24 - INFO - Downloading Public Suffix List from https://publicsuffix.org/list/public_suffix_list.dat
2025-05-17 10:15:26 - INFO - Downloaded PSL (231854 bytes)
2025-05-17 10:15:26 - INFO - PSL Version: 2025-05-12_07-25-20_UTC
2025-05-17 10:15:26 - INFO - PSL Commit: 823beb1425def931c8b0b170a6bc33b424c3f9b0
2025-05-17 10:15:26 - INFO - Parsing PSL content...
2025-05-17 10:15:28 - INFO - Parsed 8531 PSL entries (1531 ICANN domains in lookup table)
2025-05-17 10:15:28 - INFO - Normalizing private domains...
2025-05-17 10:15:29 - INFO - Processing 8531 PSL entries in batches of 10...
...
2025-05-17 10:45:26 - INFO - Saving extended version with 8531 entries to public_suffix_list.extended.json
2025-05-17 10:45:27 - INFO - Saving standard version with 8531 entries to public_suffix_list.json
2025-05-17 10:45:27 - INFO - Saving minimal version with 8531 entries to public_suffix_list.min.json
2025-05-17 10:45:27 - INFO - Saving version information to public_suffix_list.version.json
2025-05-17 10:45:27 - INFO - All JSON files successfully saved
2025-05-17 10:45:27 - INFO - PSL Parser completed in 1804.32 seconds
```

## Output Files

The script generates four different JSON files:

### 1. `public_suffix_list.extended.json`

The most comprehensive output with all metadata:

```json
{
  "psl_entry_string": "psl.entry.example.com",
  "psl_domain": "psl.entry.example.com",
  "section": "private",
  "is_wildcard": false,
  "is_negation": false,
  "requestor": {
    "requestor_description": "Requestor Org : https://example.com",
    "requestor_contact_name": "Requestor Name",
    "requestor_contact_email": "Requestor Email"
  },
  "dns": {
    "is_dns_error": true
  },
  "registry_records": {
    "reserved": false,
    "registered": true,
    "registrar": "Example Registrar",
    "registrar_url": "https://example.com",
    "creation_date": "2020-01-01T00:00:00Z",
    "creation_date_iso8601": "2020-01-01T00:00:00Z",
    "expiration_date": "2025-01-01T00:00:00Z",
    "expiration_date_iso8601": "2025-01-01T00:00:00Z",
    "updated_date": "2023-01-01T00:00:00Z",
    "updated_date_iso8601": "2023-01-01T00:00:00Z",
    "status": [
      {
        "text": "clientTransferProhibited",
        "url": "https://icann.org/epp#clientTransferProhibited"
      }
    ],
    "nameServers": [
      "ns1.example.com",
      "ns2.example.com"
    ],
    "age": "5Y 4Mo 16D",
    "age_seconds": 168753600,
    "remaining": "7Mo 14D",
    "remaining_seconds": 19440000,
    "grace_period": false,
    "redemption_period": false,
    "pending_delete": false
  },
  "icann_normalized_domain": "example.com",
  "icann_tld": "id"
}
```

### 2. `public_suffix_list.json`

Standard version with essential information:

```json
{
  "psl_entry_string": "psl.entry.example.com",
  "psl_domain": "psl.entry.example.com",
  "section": "private",
  "is_wildcard": false,
  "is_negation": false,
  "requestor": {
    "requestor_description": "Requestor Org : https://example.com",
    "requestor_contact_name": "Requestor Name",
    "requestor_contact_email": "Requestor Email"
  },
  "icann_normalized_domain": "example.com",
  "icann_tld": "id"
}
```

### 3. `public_suffix_list.min.json`

Minimal version with basic domain information:

```json
{
  "psl_entry_string": "psl.entry.example.com",
  "psl_domain": "psl.entry.example.com",
  "section": "private",
  "is_wildcard": false,
  "is_negation": false
}
```

### 4. `public_suffix_list.version.json`

Version information extracted from the PSL:

```json
{
  "version": "2025-05-12_07-25-20_UTC",
  "commit": "823beb1425def931c8b0b170a6bc33b424c3f9b0",
  "date": "2025-05-17 10:45:27 UTC"
}
```

## Understanding the PSL Format

The Public Suffix List is organized into two main sections:

1. **ICANN Domains**: Official top-level domains approved by ICANN
2. **Private Domains**: Other domains that function as effective TLDs

The PSL uses special notation:
- `*.domain`: Wildcard notation indicating all subdomains are included
- `!domain`: Negation notation excluding a specific domain from a wildcard rule

Each section contains blocks of domains with associated metadata in comments:

```
// Organization : https://example.org
// Submitted by Contact Name <email@example.org> 2025-01-01
domain.tld
another.domain.tld
```

The parser processes these blocks, maintaining the association between comments and domains within each block.

## Domain Processing

### Domain Normalization

For private domains, the parser determines the publicly registrable namespace:

```python
def _normalize_domain(self, domain: str) -> Tuple[str, str]:
    """
    Normalize a private domain to its publicly registrable form using ICANN domains.
    Returns the normalized domain and the matching ICANN TLD.
    """
    parts = domain.split('.')
    
    # Try different suffix combinations to find a match in ICANN domains
    for i in range(len(parts)):
        potential_suffix = '.'.join(parts[i:])
        if potential_suffix in self.icann_domains:
            if i == 0:
                # The whole domain is an ICANN domain
                return domain, potential_suffix
            else:
                # Found a matching ICANN suffix
                normalized = '.'.join(parts[i-1:])
                return normalized, potential_suffix
    
    # If no match found in ICANN domains, fall back to the top-level domain
    if len(parts) > 1:
        tld = parts[-1]
        return domain, tld
    else:
        # If it's a single-part domain, use it as its own TLD
        return domain, domain
```

### Requestor Information Extraction

Comments in each domain block may contain requestor information:

```python
def _extract_requestor_info(self, comments: List[str]) -> Dict[str, Optional[str]]:
    """Extract requestor information from comments"""
    requestor_info = {
        "requestor_description": None,
        "requestor_contact_name": None,
        "requestor_contact_email": None,
    }
    
    if not comments:
        return requestor_info
        
    # First comment is always the description
    requestor_info["requestor_description"] = comments[0]
    
    # Look for submission information in any comment
    for comment in comments:
        if "Submitted by" in comment:
            # Extract name and email using regex
            # ...
```

### DNS Checks

The parser uses Cloudflare's DNS over HTTPS (DoH) to check for DNS errors:

```python
def check_dns(self, domain: str) -> bool:
    """
    Check if a domain has DNS errors using Cloudflare DoH.
    Returns True if there's a DNS error (NXDOMAIN), False otherwise.
    """
    # ...
```

### WHOIS Data Retrieval

The parser enriches entries with WHOIS data from a dedicated API:

```python
def fetch_whois_data(self, domain: str) -> Dict[str, Any]:
    """Fetch WHOIS data for a domain"""
    # ...
```

## Performance Considerations

### Batch Processing

To improve performance and manage API rate limits, the parser processes entries in batches:

```python
def process_entries_batch(self, batch_size: int = 10) -> None:
    """
    Process PSL entries in batches to manage rate limits better
    """
    # ...
```

### Caching

The parser implements caching to avoid redundant API calls:

```python
# Return from cache if available
if domain in self.whois_cache:
    logger.debug(f"Using cached WHOIS data for {domain}")
    return self.whois_cache[domain]
```

### Retry Mechanism

The parser includes a retry mechanism for failed network requests:

```python
for attempt in range(MAX_RETRIES):
    try:
        # API call
        # ...
    except requests.RequestException as e:
        logger.warning(f"Request failed: {str(e)}")
        if attempt < MAX_RETRIES - 1:
            time.sleep(api_interval_seconds)
```

## Troubleshooting

### Common Issues

1. **API Rate Limiting**
   - Increase `api_interval_seconds` to add more delay between requests
   - Decrease `batch_size` to process fewer entries at once

2. **Network Errors**
   - Check your internet connection
   - Verify the API endpoints are accessible
   - Increase `api_timeout_seconds` for slow connections

3. **Memory Issues**
   - For very large PSL files, consider processing in smaller chunks
   - Implement a disk-based cache for WHOIS results

### Debug Logging

Enable detailed logging to help diagnose issues:

```python
debug_mode = True
debug_log_enabled = True
```

This creates a `debug.log` file with verbose information about the parsing process.

## Advanced Usage

### Custom WHOIS API

To use a different WHOIS API:

1. Update the `api_endpoint_url` and any required headers
2. Modify `_process_whois_response()` to handle the new API format

### Integration with Other Systems

#### Database Integration

You can adapt the script to store results in a database:

```python
import sqlite3

def save_to_database(self, connection_string: str) -> None:
    """Save the processed PSL entries to a database"""
    conn = sqlite3.connect(connection_string)
    cursor = conn.cursor()
    
    # Create table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS psl_entries (
        id INTEGER PRIMARY KEY,
        psl_entry_string TEXT,
        psl_domain TEXT,
        section TEXT,
        is_wildcard INTEGER,
        is_negation INTEGER,
        requestor_description TEXT,
        requestor_contact_name TEXT,
        requestor_contact_email TEXT,
        icann_normalized_domain TEXT,
        icann_tld TEXT
    )
    ''')
    
    # Insert entries
    # ...
```

#### API Service

You can expose the PSL data as an API:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class PSLHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/psl":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(psl_entries).encode())
        # ...
```

---

This project is not affiliated with the Public Suffix List maintainers or ICANN.