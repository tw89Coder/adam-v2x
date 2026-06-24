import re
import urllib.parse
import requests
import time
import sys
import os

# ==========================================
# INDUSTRIAL CLI DESIGN (ANSI ESCAPE CODES)
# ==========================================
class Style:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    INFO = '\033[1;36m'     # Bright Cyan
    PASS = '\033[1;32m'     # Bright Green
    MINOR = '\033[1;34m'    # Bright Blue
    WARN = '\033[1;33m'     # Bright Yellow
    GHOST = '\033[1;31m'    # Bright Red
    FAKE = '\033[1;41;37m'  # Red Background
    SPEC = '\033[1;35m'     # Bright Magenta
    LINE = '\033[38;5;240m' # Dark Gray Divider

TEX_FILE = "main.tex"
COL_WIDTH_TITLE = 50        

def extract_bibitems_from_tex(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        match = re.search(r'\\begin\{thebibliography\}(.*?)\\end\{thebibliography\}', content, re.DOTALL)
        if not match:
            print(f"{Style.FAKE}[ ERROR ]{Style.RESET} Target block '\\begin{{thebibliography}}' not found in {filepath}")
            return []
            
        bib_content = match.group(1)
        raw_items = re.split(r'\\bibitem(?:\[.*?\])?\{.*?\}', bib_content)[1:]
        
        cleaned_items = []
        for item in raw_items:
            item = item.strip()
            if not item: continue
            item = item.replace('\n', ' ')
            item = re.sub(r'\\[a-zA-Z]+\{([^}]+)\}', r'\1', item) 
            item = item.replace("~", " ").replace("``", "").replace("''", "").replace('"', '')
            item = re.sub(r'\s+', ' ', item)
            cleaned_items.append(item)
            
        return cleaned_items
    except FileNotFoundError:
        print(f"{Style.FAKE}[ ERROR ]{Style.RESET} Target file not found: {filepath}")
        return []

def get_title_similarity(cr_title, citation_text):
    cr_words = set(re.findall(r'[a-z0-9]+', cr_title.lower()))
    cit_words = set(re.findall(r'[a-z0-9]+', citation_text.lower()))
    if not cr_words: return 0.0
    return len(cr_words.intersection(cit_words)) / len(cr_words)

def audit_candidate(item, citation_text):
    cr_title = item.get('title', [''])[0]
    t_ratio = get_title_similarity(cr_title, citation_text)
    
    authors = item.get('author', [])
    first_author_family = authors[0].get('family', '') if authors else ''
    author_match = first_author_family.lower() in citation_text.lower() if first_author_family else False
    
    year_parts = item.get('issued', {}).get('date-parts', [[0]])[0]
    cr_year = str(year_parts[0]) if year_parts and len(year_parts) > 0 else "0000"
    year_match = cr_year in citation_text
    
    venue = item.get('container-title', [''])[0] if item.get('container-title') else 'Unknown_Venue'
    doi = item.get('DOI', 'NO_DOI')
    
    audit_score = (t_ratio * 70) + (20 if author_match else 0) + (10 if year_match else 0)
    
    return {
        'doi': doi, 'cr_title': cr_title, 'venue': venue,
        'cr_year': cr_year, 't_ratio': t_ratio, 
        'author_match': author_match, 'year_match': year_match, 'audit_score': audit_score
    }

def check_crossref(citation_text):
    headers = {'User-Agent': 'TexRefAuditor/3.1 (mailto:admin@localhost)'}
    
    # 1. DIRECT DOI VERIFICATION
    # Fix: Handles LaTeX escaped underscores in DOI (e.g. \_12 -> _12)
    doi_match = re.search(r'(10\.\d{4,9}/[-._\\;()/:A-Z0-9]+)', citation_text, re.IGNORECASE)
    if doi_match:
        explicit_doi = doi_match.group(1).rstrip('.,').replace('\\_', '_')
        url = f"https://api.crossref.org/works/{explicit_doi}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                item = resp.json().get('message', {})
                audit = audit_candidate(item, citation_text)
                if audit['t_ratio'] < 0.5:
                    return "WARN", explicit_doi, f"DOI FOUND BUT TEXT MISMATCH | Found: {audit['cr_title']}"
                return "PASS", explicit_doi, f"EXPLICIT_DOI_VERIFIED | Venue: {audit['venue']} ({audit['cr_year']})"
            else:
                return "FAKE", explicit_doi, "DEAD_DOI | The provided DOI does not exist in Crossref."
        except Exception as e:
            return "FAKE", "API_ERROR", str(e)

    # 2. ETSI / 3GPP SPECIFICATION BYPASS
    spec_pattern = r'((?:ETSI|3GPP)\s+(?:GS|TS|EN|TR)?\s*[A-Z0-9\-\.\s_:\(\)]+?\d+[\d\s\-\.]*)'
    spec_match = re.search(spec_pattern, citation_text, re.IGNORECASE)
    if spec_match:
        extracted_spec_id = re.sub(r'\s+', ' ', spec_match.group(1)).strip().upper()
        return "SPEC", "NO_DOI_REGISTERED", f"LOCAL_SPEC_MATCH | Standard ID: '{extracted_spec_id}'"

    # 3. ADVANCED FREE-TEXT SEARCH
    query = urllib.parse.quote(citation_text)
    url = f"https://api.crossref.org/works?query.bibliographic={query}&rows=5"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        items = response.json().get('message', {}).get('items', [])
        
        if not items:
            return "FAKE", "NO_MATCH", "Zero records found. High probability of hallucination."
            
        candidates = [audit_candidate(item, citation_text) for item in items]
        candidates.sort(key=lambda x: x['audit_score'], reverse=True)
        best = candidates[0]
        
        doi = best['doi']
        title_disp = best['cr_title'][:40] + "..." if len(best['cr_title']) > 40 else best['cr_title']
        
        if best['t_ratio'] > 0.85 and best['author_match'] and best['year_match']:
            return "PASS", doi, f"ALL_MATCH | Venue: {best['venue']} ({best['cr_year']})"
        elif best['t_ratio'] > 0.75:
            warns = []
            if not best['author_match']: warns.append("AUTHOR_MISMATCH")
            if not best['year_match']: warns.append(f"YEAR_MISMATCH(got {best['cr_year']})")
            msg = f"{', '.join(warns)} | Title: {title_disp}" if warns else f"VENUE_DRIFT | Title: {title_disp}"
            return "MINOR", doi, msg
        elif best['t_ratio'] > 0.50:
            return "WARN", doi, f"PARTIAL_TITLE ({int(best['t_ratio']*100)}% match) | {title_disp}"
        else:
            return "GHOST", "SUSPECTED_HALLUCINATION", f"Top match title similarity only {int(best['t_ratio']*100)}%. Title: {title_disp}"
            
    except Exception as e:
        return "FAKE", "API_ERROR", str(e)

def print_legend():
    """Prints a user-friendly legend explaining the status codes."""
    print(f"\n{Style.INFO}{Style.BOLD}=== SYSTEM LEGEND (HOW TO READ RESULTS) ==={Style.RESET}")
    print(f"{Style.PASS}[ PASS ]{Style.RESET} Perfect match. DOI, Title, Author, and Year all align with Crossref database.")
    print(f"{Style.MINOR}[ MINOR]{Style.RESET} High match, but minor metadata drift (e.g., Year off by 1, Author typo). Usually safe.")
    print(f"{Style.WARN}[ WARN ]{Style.RESET} Partial match, OR an explicit DOI points to a COMPLETELY DIFFERENT paper (Risk of DOI Hijacking).")
    print(f"{Style.GHOST}[GHOST?]{Style.RESET} Severe warning. API found a paper, but title similarity is <50%. Likely an AI Hallucination.")
    print(f"{Style.FAKE}[ FAKE ]{Style.RESET} Critical failure. Explicit DOI is dead (404), or absolutely no search results exist.")
    print(f"{Style.SPEC}[ SPEC ]{Style.RESET} Valid 3GPP/ETSI standard. Bypassed Crossref API (specs usually lack DOIs).\n")

def print_header(total_count):
    divider = f"{Style.LINE}{'-' * 98}{Style.RESET}"
    print(divider)
    print(f"{Style.INFO}{Style.BOLD}CROSSREF HYBRID METADATA VALIDATOR ENGINE v3.1 (TMC AUDIT EDITION){Style.RESET}")
    print(divider)
    print(f"TARGET_FILE   : {Style.BOLD}{TEX_FILE}{Style.RESET}")
    print(f"TOTAL_RECS    : {Style.BOLD}{total_count}{Style.RESET} records parsed")
    print(divider)
    
    h_status = "STATUS".ljust(10)
    h_citation = "CITED STRING EXTRACT (TRUNCATED)".ljust(COL_WIDTH_TITLE)
    h_metric = "RESOLVED DOI / DECISION"
    
    print(f"{Style.DIM}{h_status} | {h_citation} | {h_metric}{Style.RESET}")
    print(divider)

def print_row(status, preview, metric, details):
    if status == "PASS": status_str = f"{Style.PASS}[ PASS ]{Style.RESET}  "
    elif status == "MINOR": status_str = f"{Style.MINOR}[ MINOR]{Style.RESET}  "
    elif status == "WARN": status_str = f"{Style.WARN}[ WARN ]{Style.RESET}  "
    elif status == "SPEC": status_str = f"{Style.SPEC}[ SPEC ]{Style.RESET}  "
    elif status == "GHOST": status_str = f"{Style.GHOST}[GHOST?]{Style.RESET}  "
    else: status_str = f"{Style.FAKE}[ FAKE ]{Style.RESET}  "

    preview_clean = preview.replace('\n', ' ')
    if len(preview_clean) > COL_WIDTH_TITLE:
        preview_clean = preview_clean[:COL_WIDTH_TITLE - 3] + "..."
    preview_str = preview_clean.ljust(COL_WIDTH_TITLE)

    print(f"{status_str} | {preview_str} | {Style.BOLD}{metric}{Style.RESET}")
    print(f"           {Style.DIM}-> DETAILS: {details}{Style.RESET}")

def main():
    if os.name == 'nt':
        os.system('color') 
        
    citations = extract_bibitems_from_tex(TEX_FILE)
    if not citations:
        sys.exit(1)

    print_legend()
    print_header(len(citations))
    
    for citation in citations:
        status, metric, details = check_crossref(citation)
        print_row(status, citation, metric, details)
        time.sleep(0.3) 
        
    print(f"{Style.LINE}{'-' * 98}{Style.RESET}")
    print(f"{Style.INFO}Audit complete.{Style.RESET} Prioritize resolving {Style.GHOST}[GHOST?]{Style.RESET} and {Style.FAKE}[ FAKE ]{Style.RESET} entries.")

if __name__ == "__main__":
    main()