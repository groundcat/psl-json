#!/usr/bin/env python3
"""
Public Suffix List Parser

This script downloads and parses the Public Suffix List (PSL) and creates
a structured JSON file with additional metadata for each entry.
"""

import json
import logging
import re
import requests
import time
import sys
import os
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Tuple
import concurrent.futures

# Configuration
psl_url = "https://publicsuffix.org/list/public_suffix_list.dat"
api_endpoint_url = "https://whois-api.publicsuffix.de/api/?domain="
api_additional_headers = {}  # Empty by default
api_timeout_seconds = 5
api_interval_seconds = 1
debug_mode = True
debug_log_enabled = True
MAX_RETRIES = 3

# Setup logging
log_level = logging.DEBUG if debug_mode else logging.INFO
log_handlers = [logging.StreamHandler()]

if debug_log_enabled:
    log_handlers.append(logging.FileHandler('debug.log', mode='w'))

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger(__name__)


class PSLParser:
    """Parser for the Public Suffix List"""
    
    def __init__(self):
        self.icann_domains: Set[str] = set()
        self.psl_entries: List[Dict[str, Any]] = []
        self.whois_cache: Dict[str, Dict[str, Any]] = {}
        self.version_info = {
            "version": None,
            "commit": None,
            "date": None
        }
    
    def download_psl(self) -> str:
        """Download the Public Suffix List"""
        logger.info("Downloading Public Suffix List from %s", psl_url)
        
        for attempt in range(MAX_RETRIES):
            try:
                response = requests.get(psl_url, timeout=api_timeout_seconds)
                response.raise_for_status()
                content = response.text
                # Normalize requestor info line by replacing "Confirmed by" with "Submitted by"
                content = content.replace("Confirmed by", "Submitted by")
                logger.info("Downloaded PSL (%d bytes)", len(content))
                return content
            except requests.RequestException as e:
                logger.warning(f"Download attempt {attempt+1}/{MAX_RETRIES} failed: {str(e)}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2)
        
        raise RuntimeError(f"Failed to download PSL after {MAX_RETRIES} attempts")
    
    def extract_version_info(self, psl_content: str) -> None:
        """Extract version and commit information from PSL header"""
        lines = psl_content.splitlines()
        
        for line in lines:
            line = line.strip()
            if "VERSION:" in line:
                self.version_info["version"] = line.replace("// VERSION:", "").strip()
            elif "COMMIT:" in line:
                self.version_info["commit"] = line.replace("// COMMIT:", "").strip()
            
            # Stop after we've found what we need
            if self.version_info["version"] and self.version_info["commit"]:
                break
        
        # Set date to current date if not found
        if not self.version_info["date"]:
            self.version_info["date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        logger.info(f"PSL Version: {self.version_info['version']}")
        logger.info(f"PSL Commit: {self.version_info['commit']}")
    
    def parse_psl(self, psl_content: str) -> None:
        """Parse the PSL content and extract entries"""
        # First extract version information
        self.extract_version_info(psl_content)
        
        lines = psl_content.splitlines()
        
        current_section = None
        current_block_comments = []
        current_block_requestor_info = None
        domains_in_current_block = []
        
        logger.info("Parsing PSL content...")
        
        for line in lines:
            line = line.strip()
            
            # Empty line indicates the end of a block
            if not line:
                # Process any domains collected in the current block
                if domains_in_current_block and current_section:
                    for domain in domains_in_current_block:
                        self._process_entry(domain, current_section, current_block_requestor_info)
                
                # Reset for the new block
                current_block_comments = []
                current_block_requestor_info = None
                domains_in_current_block = []
                continue
            
            # Detect section changes
            if line == "// ===BEGIN ICANN DOMAINS===":
                current_section = "icann"
                current_block_comments = []
                current_block_requestor_info = None
                domains_in_current_block = []
                logger.debug("Entering ICANN section")
                continue
            elif line == "// ===END ICANN DOMAINS===":
                current_section = None
                current_block_comments = []
                current_block_requestor_info = None
                domains_in_current_block = []
                logger.debug("Exiting ICANN section")
                continue
            elif line == "// ===BEGIN PRIVATE DOMAINS===":
                current_section = "private"
                current_block_comments = []
                current_block_requestor_info = None
                domains_in_current_block = []
                logger.debug("Entering PRIVATE section")
                continue
            elif line == "// ===END PRIVATE DOMAINS===":
                current_section = None
                current_block_comments = []
                current_block_requestor_info = None
                domains_in_current_block = []
                logger.debug("Exiting PRIVATE section")
                continue
            
            # Process comments - add to the current block's comments
            if line.startswith("//"):
                comment = line[2:].strip()
                current_block_comments.append(comment)
                
                # Extract requestor info for this block
                if current_block_requestor_info is None:
                    current_block_requestor_info = self._extract_requestor_info(current_block_comments)
                else:
                    # Update the existing requestor info with any new information
                    updated_info = self._extract_requestor_info(current_block_comments)
                    
                    # Only update fields that were previously None
                    if current_block_requestor_info["requestor_description"] is None:
                        current_block_requestor_info["requestor_description"] = updated_info["requestor_description"]
                    
                    if current_block_requestor_info["requestor_contact_name"] is None:
                        current_block_requestor_info["requestor_contact_name"] = updated_info["requestor_contact_name"]
                    
                    if current_block_requestor_info["requestor_contact_email"] is None:
                        current_block_requestor_info["requestor_contact_email"] = updated_info["requestor_contact_email"]
                
                continue
            
            # Skip if we're not in a valid section
            if not current_section:
                continue
            
            # This is a domain line - add to the current block
            domains_in_current_block.append(line)
        
        # Process any remaining domains in the last block
        if domains_in_current_block and current_section:
            for domain in domains_in_current_block:
                self._process_entry(domain, current_section, current_block_requestor_info)
        
        logger.info("Parsed %d PSL entries (%d ICANN domains in lookup table)",
                   len(self.psl_entries), len(self.icann_domains))
    
    def _process_entry(self, line: str, section: str, requestor_info: Dict[str, Optional[str]]) -> None:
        """Process a single PSL entry"""
        psl_entry_string = line
        
        # Check if this is a wildcard or negation domain
        is_wildcard = psl_entry_string.startswith("*.")
        is_negation = psl_entry_string.startswith("!")
        
        # Strip leading '*.' or '!'
        psl_domain = psl_entry_string
        if is_wildcard:
            psl_domain = psl_entry_string[2:]
        elif is_negation:
            psl_domain = psl_entry_string[1:]
        
        # Store ICANN domains in lookup set
        if section == "icann":
            self.icann_domains.add(psl_domain)
        
        # Use the provided requestor info
        if requestor_info is None:
            requestor_info = {
                "requestor_description": None,
                "requestor_contact_name": None,
                "requestor_contact_email": None,
            }
        
        # For debugging - show requestor info for this entry
        if debug_mode:
            logger.debug(f"Domain {psl_domain} - Requestor info: {requestor_info}")
        
        # Create entry object
        entry = {
            "psl_entry_string": psl_entry_string,
            "psl_domain": psl_domain,
            "section": section,
            "is_wildcard": is_wildcard,
            "is_negation": is_negation,
            "requestor": requestor_info,
            "dns": {"is_dns_error": False},  # Default value, will be updated later
            "registry_records": {}  # Will be populated later
        }
        
        # For private domains, add placeholders - we'll calculate after all ICANN domains are collected
        if section == "private":
            entry["icann_normalized_domain"] = None
            entry["icann_tld"] = None
        else:
            # For ICANN domains, the normalized domain is the domain itself, and the TLD is also the domain itself
            entry["icann_normalized_domain"] = psl_domain
            entry["icann_tld"] = psl_domain
        
        self.psl_entries.append(entry)
    
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
                # Debug the actual line
                logger.debug(f"Processing 'Submitted by' line: {comment}")
                
                # First, try the standard format with name and <email>
                match = re.search(r"Submitted by\s+([^<]+)\s*<([^>]+)>", comment)
                if match:
                    requestor_info["requestor_contact_name"] = match.group(1).strip()
                    requestor_info["requestor_contact_email"] = match.group(2).strip()
                    logger.debug(f"Extracted using pattern 1: name={requestor_info['requestor_contact_name']}, email={requestor_info['requestor_contact_email']}")
                    break
                    
                # If that fails, try to extract just an email address
                email_match = re.search(r'[\w\.-]+@[\w\.-]+', comment)
                if email_match:
                    requestor_info["requestor_contact_email"] = email_match.group(0)
                    
                    # Try to extract name by looking at text before the email
                    name_part = comment.split(email_match.group(0))[0].replace("Submitted by", "").strip()
                    if name_part:
                        # Remove any trailing punctuation or special characters
                        name_part = re.sub(r'[<>:,.\s]+$', '', name_part)
                        if name_part:
                            requestor_info["requestor_contact_name"] = name_part
                            
                    logger.debug(f"Extracted using pattern 2: name={requestor_info['requestor_contact_name']}, email={requestor_info['requestor_contact_email']}")
                    break
        
        return requestor_info
    
    def normalize_private_domains(self) -> None:
        """
        Normalize all private domains after all ICANN domains have been collected.
        This is more efficient than doing it during initial parsing.
        """
        logger.info("Normalizing private domains...")
        
        for entry in self.psl_entries:
            if entry["section"] == "private":
                domain = entry["psl_domain"]
                icann_normalized_domain, icann_tld = self._normalize_domain(domain)
                entry["icann_normalized_domain"] = icann_normalized_domain
                entry["icann_tld"] = icann_tld
    
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
            logger.debug(f"No ICANN match for {domain}, falling back to TLD: {tld}")
            return domain, tld
        else:
            # If it's a single-part domain, use it as its own TLD
            logger.debug(f"Single-part domain: {domain}")
            return domain, domain
    
    def check_dns(self, domain: str) -> bool:
        """
        Check if a domain has DNS errors using Cloudflare DoH.
        Returns True if there's a DNS error (NXDOMAIN), False otherwise.
        Uses ANY query type to check for existence of any DNS records.
        """
        # Skip wildcard and negation domains
        if "*" in domain or domain.startswith("!"):
            return False
        
        try:
            url = "https://cloudflare-dns.com/dns-query"
            headers = {
                "Accept": "application/dns-json",
            }
            params = {
                "name": domain,
                "type": "ANY",
            }
            
            for attempt in range(MAX_RETRIES):
                try:
                    response = requests.get(
                        url, 
                        headers=headers, 
                        params=params, 
                        timeout=api_timeout_seconds
                    )
                    response.raise_for_status()
                    data = response.json()
                    
                    # Check for NXDOMAIN status (code 3)
                    # Also check if we got any answers in the response
                    return data.get("Status") == 3 or not data.get("Answer", [])
                
                except requests.RequestException as e:
                    logger.debug(f"DNS check attempt {attempt+1}/{MAX_RETRIES} failed for {domain}: {str(e)}")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(1)
            
            return False
        
        except Exception as e:
            logger.debug(f"DNS check error for {domain}: {str(e)}")
            return False
    
    def fetch_whois_data(self, domain: str) -> Dict[str, Any]:
        """Fetch WHOIS data for a domain"""
        # Return from cache if available
        if domain in self.whois_cache:
            logger.debug(f"Using cached WHOIS data for {domain}")
            return self.whois_cache[domain]
        
        # Skip wildcard and negation domains
        if "*" in domain or domain.startswith("!"):
            return self._empty_registry_records()
        
        logger.debug(f"Fetching WHOIS data for {domain}")
        
        for attempt in range(MAX_RETRIES):
            try:
                url = f"{api_endpoint_url}{domain}"
                response = requests.get(
                    url, 
                    headers=api_additional_headers,
                    timeout=api_timeout_seconds
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Extract the registry records
                        registry_records = self._process_whois_response(data)
                        # Cache the result
                        self.whois_cache[domain] = registry_records
                        return registry_records
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON from WHOIS API for {domain}: {str(e)}")
                else:
                    logger.warning(f"WHOIS API returned status {response.status_code} for {domain}")
                
                if attempt < MAX_RETRIES - 1:
                    time.sleep(api_interval_seconds)
            
            except requests.RequestException as e:
                logger.warning(f"WHOIS request failed for {domain}: {str(e)}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(api_interval_seconds)
        
        # Return empty data after all retries fail
        return self._empty_registry_records()
    
    def _process_whois_response(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process the WHOIS API response to extract registry records.
        """
        # Start with empty registry records
        registry_records = self._empty_registry_records()
        
        # Check if the response has the expected structure
        if 'code' in response_data and 'data' in response_data:
            # Extract the actual WHOIS data from the nested structure
            whois_data = response_data.get('data', {})
            
            # Map fields with different names in API response to our registry_records structure
            field_mapping = {
                "reserved": "reserved",
                "registered": "registered",
                "registrar": "registrar",
                "registrarURL": "registrar_url",
                "creationDate": "creation_date",
                "creationDateISO8601": "creation_date_iso8601",
                "expirationDate": "expiration_date",
                "expirationDateISO8601": "expiration_date_iso8601",
                "updatedDate": "updated_date",
                "updatedDateISO8601": "updated_date_iso8601",
                "status": "status",
                "nameServers": "nameServers",
                "age": "age",
                "ageSeconds": "age_seconds",
                "remaining": "remaining",
                "remainingSeconds": "remaining_seconds",
                "gracePeriod": "grace_period",
                "redemptionPeriod": "redemption_period",
                "pendingDelete": "pending_delete"
            }
            
            # Map the fields
            for api_field, our_field in field_mapping.items():
                if api_field in whois_data:
                    registry_records[our_field] = whois_data[api_field]
        else:
            # If response doesn't have expected structure, try direct mapping
            logger.warning("Unexpected WHOIS API response structure")
            for field in registry_records:
                if field in response_data:
                    registry_records[field] = response_data[field]
        
        return registry_records
    
    def _empty_registry_records(self) -> Dict[str, Any]:
        """Return an empty registry records structure"""
        return {
            "reserved": None,
            "registered": None,
            "registrar": None,
            "registrar_url": None,
            "creation_date": None,
            "creation_date_iso8601": None,
            "expiration_date": None,
            "expiration_date_iso8601": None,
            "updated_date": None,
            "updated_date_iso8601": None,
            "status": [],
            "nameServers": [],
            "age": None,
            "age_seconds": None,
            "remaining": None,
            "remaining_seconds": None,
            "grace_period": None,
            "redemption_period": None,
            "pending_delete": None
        }
    
    def process_entries(self) -> None:
        """Process all PSL entries: check DNS and fetch WHOIS data"""
        # First, normalize private domains now that we have all ICANN domains
        self.normalize_private_domains()
        
        total_entries = len(self.psl_entries)
        logger.info(f"Processing {total_entries} PSL entries (DNS checks and WHOIS lookups)...")
        
        for i, entry in enumerate(self.psl_entries):
            domain = entry["psl_domain"]
            
            # Progress reporting
            if i % 10 == 0 or i == total_entries - 1:
                if debug_mode:
                    logger.info(f"Processing entry {i+1}/{total_entries}: {domain}")
                else:
                    print(f"Processing: {i+1}/{total_entries} entries", end="\r")
            
            try:
                # Check DNS
                is_dns_error = self.check_dns(domain)
                entry["dns"] = {"is_dns_error": is_dns_error}
                
                # Determine which domain to use for WHOIS lookup
                lookup_domain = entry.get("icann_normalized_domain")
                if not lookup_domain or lookup_domain == "":
                    lookup_domain = domain
                
                # Fetch WHOIS data
                registry_records = self.fetch_whois_data(lookup_domain)
                entry["registry_records"] = registry_records
                
            except Exception as e:
                logger.error(f"Error processing {domain}: {str(e)}")
                # Ensure entry has all required fields even if an error occurs
                if "dns" not in entry:
                    entry["dns"] = {"is_dns_error": False}
                if "registry_records" not in entry:
                    entry["registry_records"] = self._empty_registry_records()
            
            # Rate limiting to avoid API throttling
            time.sleep(api_interval_seconds)
        
        if not debug_mode:
            print("\nProcessing complete!")
    
    def process_entries_batch(self, batch_size: int = 10) -> None:
        """
        Process PSL entries in batches to manage rate limits better
        """
        # First, normalize private domains
        self.normalize_private_domains()
        
        total_entries = len(self.psl_entries)
        logger.info(f"Processing {total_entries} PSL entries in batches of {batch_size}...")
        
        # Process in batches
        for start_idx in range(0, total_entries, batch_size):
            end_idx = min(start_idx + batch_size, total_entries)
            batch = self.psl_entries[start_idx:end_idx]
            
            if not debug_mode:
                print(f"Processing batch: {start_idx+1}-{end_idx} of {total_entries}", end="\r")
            else:
                logger.info(f"Processing batch: {start_idx+1}-{end_idx} of {total_entries}")
            
            # Process each entry in the batch
            for entry in batch:
                domain = entry["psl_domain"]
                
                try:
                    # Check DNS
                    is_dns_error = self.check_dns(domain)
                    entry["dns"] = {"is_dns_error": is_dns_error}
                    
                    # Determine which domain to use for WHOIS lookup
                    lookup_domain = entry.get("icann_normalized_domain")
                    if not lookup_domain or lookup_domain == "":
                        lookup_domain = domain
                    
                    # Fetch WHOIS data
                    registry_records = self.fetch_whois_data(lookup_domain)
                    entry["registry_records"] = registry_records
                    
                except Exception as e:
                    logger.error(f"Error processing {domain}: {str(e)}")
                    # Ensure entry has all required fields even if an error occurs
                    if "dns" not in entry:
                        entry["dns"] = {"is_dns_error": False}
                    if "registry_records" not in entry:
                        entry["registry_records"] = self._empty_registry_records()
            
            # Brief pause between batches
            time.sleep(api_interval_seconds * 2)
        
        if not debug_mode:
            print("\nProcessing complete!")
    
    def create_standard_json(self) -> List[Dict]:
        """Create the standard version of the JSON output"""
        standard_entries = []
        
        for entry in self.psl_entries:
            standard_entry = {
                "psl_entry_string": entry["psl_entry_string"],
                "psl_domain": entry["psl_domain"],
                "section": entry["section"],
                "is_wildcard": entry["is_wildcard"],
                "is_negation": entry["is_negation"],
                "requestor": entry["requestor"],
                "icann_normalized_domain": entry["icann_normalized_domain"],
                "icann_tld": entry["icann_tld"]
            }
            standard_entries.append(standard_entry)
        
        return standard_entries
    
    def create_minimal_json(self) -> List[Dict]:
        """Create the minimal version of the JSON output"""
        minimal_entries = []
        
        for entry in self.psl_entries:
            minimal_entry = {
                "psl_entry_string": entry["psl_entry_string"],
                "psl_domain": entry["psl_domain"],
                "section": entry["section"],
                "is_wildcard": entry["is_wildcard"],
                "is_negation": entry["is_negation"]
            }
            minimal_entries.append(minimal_entry)
        
        return minimal_entries
    
    def save_version_info(self) -> None:
        """Save the version information to a separate file"""
        version_file = "public_suffix_list.version.json"
        logger.info(f"Saving version information to {version_file}")
        
        with open(version_file, 'w', encoding='utf-8') as f:
            json.dump(self.version_info, f, indent=2, ensure_ascii=False)
    
    def save_to_json(self) -> None:
        """Save the processed PSL entries to JSON files with different detail levels"""
        # Save full version
        extended_file = "public_suffix_list.extended.json"
        logger.info(f"Saving extended version with {len(self.psl_entries)} entries to {extended_file}")
        with open(extended_file, 'w', encoding='utf-8') as f:
            json.dump(self.psl_entries, f, indent=2, ensure_ascii=False)
        
        # Save standard version
        standard_file = "public_suffix_list.json"
        standard_entries = self.create_standard_json()
        logger.info(f"Saving standard version with {len(standard_entries)} entries to {standard_file}")
        with open(standard_file, 'w', encoding='utf-8') as f:
            json.dump(standard_entries, f, indent=2, ensure_ascii=False)
        
        # Save minimal version
        minimal_file = "public_suffix_list.min.json"
        minimal_entries = self.create_minimal_json()
        logger.info(f"Saving minimal version with {len(minimal_entries)} entries to {minimal_file}")
        with open(minimal_file, 'w', encoding='utf-8') as f:
            json.dump(minimal_entries, f, indent=2, ensure_ascii=False)
        
        # Save version information
        self.save_version_info()
        
        logger.info("All JSON files successfully saved")


def main():
    """Main function to run the PSL parser"""
    start_time = time.time()
    logger.info("PSL Parser started")
    
    parser = PSLParser()
    
    try:
        # Download and parse PSL
        psl_content = parser.download_psl()
        parser.parse_psl(psl_content)
        
        # Process entries
        parser.process_entries_batch()
        
        # Save to JSON files
        parser.save_to_json()
        
        elapsed_time = time.time() - start_time
        logger.info(f"PSL Parser completed in {elapsed_time:.2f} seconds")
    
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())