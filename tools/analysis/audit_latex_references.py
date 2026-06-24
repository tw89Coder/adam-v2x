#!/usr/bin/env python3
# tools/analysis/audit_latex_references.py
import re
import os
import sys
import time
import argparse
import requests
import urllib.parse

class Style:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    INFO = '\033[1;36m'     
    PASS = '\033[1;32m'     
    MINOR = '\033[1;34m'    
    WARN = '\033[1;33m'     
    GHOST = '\033[1;31m'    
    FAKE = '\033[1;41;37m'  
    SPEC = '\033[1;35m'     
    LINE = '\033[38;5;240m' 

COL_WIDTH_TITLE = 50

class LatexReferenceAuditor:
    """
    Automated academic citation validator querying the Crossref API registry to detect
    metadata drifting, DOI consistency errors, or malicious AI hallucinations in paper bibliographies.
    """
    def __init__(self, tex_filepath):
        self.tex_filepath = tex_filepath
        self.headers = {'User-Agent': 'TexRefAuditor/3.1 (mailto:admin@localhost)'}

    def extract_bibitems(self):
        if not os.path.exists(self.tex_filepath):
            print(f"{Style.FAKE}[ ERROR ]{Style.RESET} Targeted document manuscript not found at: '{self.tex_filepath}'")
            sys.exit(1)
            
        with open(self.tex_filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        match = re.search(r'\\begin\{thebibliography\}(.*?)\\end\{thebibliography\}', content, re.DOTALL)
        if not match:
            print(f"{Style.FAKE}[ ERROR ]{Style.RESET} Block structure '\\begin{{thebibliography}}' absent in manuscript.")
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

    def _get_title_similarity(self, cr_title, citation_text):
        cr_words = set(re.findall(r'[a-z0-9]+', cr_title.lower()))
        cit_words = set(re.findall(r'[a-z0-9]+', citation_text.lower()))
        if not cr_words: return 0.0
        return len(cr_words.intersection(cit_words)) / len(cr_words)

    def _audit_candidate(self, item, citation_text):
        cr_title = item.get('title', [''])[0]
        t_ratio = self._get_title_similarity(cr_title, citation_text)
        
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

    def verify_citation(self, citation_text):
        # 1. Direct explicit DOI identifier lookup verification
        doi_match = re.search(r'(10\.\d{4,9}/[-._\\;()/:A-Z0-9]+)', citation_text, re.IGNORECASE)
        if doi_match:
            explicit_doi = doi_match.group(1).rstrip('.,').replace('\\_', '_')
            url = f"https://api.crossref.org/works/{explicit_doi}"
            try:
                resp = requests.get(url, headers=self.headers, timeout=10)
                if resp.status_code == 200:
                    item = resp.json().get('message', {})
                    audit = self._audit_candidate(item, citation_text)
                    if audit['t_ratio'] < 0.5:
                        return "WARN", explicit_doi, f"DOI SEED CONFLICT | Mismatched title: {audit['cr_title']}"
                    return "PASS", explicit_doi, f"EXPLICIT_DOI_VERIFIED | Venue: {audit['venue']} ({audit['cr_year']})"
                else:
                    return "FAKE", explicit_doi, "DEAD_DOI | Registered target identifier returned 404 in Crossref."
            except Exception as e:
                return "FAKE", "API_ERROR", str(e)

        # 2. Local standardization specifications passthrough bypass routing
        spec_pattern = r'((?:ETSI|3GPP)\s+(?:GS|TS|EN|TR)?\s*[A-Z0-9\-\.\s_:\(\)]+?\d+[\d\s\-\.]*)'
        spec_match = re.search(spec_pattern, citation_text, re.IGNORECASE)
        if spec_match:
            extracted_spec_id = re.sub(r'\s+', ' ', spec_match.group(1)).strip().upper()
            return "SPEC", "NO_DOI_REGISTERED", f"STANDARDIZATION_MATCH | Standard ID: '{extracted_spec_id}'"

        # 3. Dynamic metadata free-text algorithmic matching search
        query = urllib.parse.quote(citation_text)
        url = f"https://api.crossref.org/works?query.bibliographic={query}&rows=5"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            items = response.json().get('message', {}).get('items', [])
            
            if not items:
                return "FAKE", "NO_MATCH", "Empty query results. Severe bibliography hallucination risk."
                
            candidates = [self._audit_candidate(item, citation_text) for item in items]
            candidates.sort(key=lambda x: x['audit_score'], reverse=True)
            best = candidates[0]
            
            doi = best['doi']
            title_disp = best['cr_title'][:40] + "..." if len(best['cr_title']) > 40 else best['cr_title']
            
            if best['t_ratio'] > 0.85 and best['author_match'] and best['year_match']:
                return "PASS", doi, f"ALL_METRICS_ALIGNED | Venue: {best['venue']} ({best['cr_year']})"
            elif best['t_ratio'] > 0.75:
                warns = []
                if not best['author_match']: warns.append("AUTHOR_MISMATCH")
                if not best['year_match']: warns.append(f"YEAR_MISMATCH({best['cr_year']})")
                return "MINOR", doi, f"{', '.join(warns)} | Title: {title_disp}"
            elif best['t_ratio'] > 0.50:
                return "WARN", doi, f"PARTIAL_MATCH ({int(best['t_ratio']*100)}%) | {title_disp}"
            else:
                return "GHOST", "SUSPECTED_HALLUCINATION", f"Low-score overlap ({int(best['t_ratio']*100)}%). Title: {title_disp}"
                
        except Exception as e:
            return "FAKE", "API_ERROR", str(e)

def print_legend():
    print(f"\n{Style.INFO}{Style.BOLD}=== REFERENCE SYSTEM DECISION AUDIT LEGEND ==={Style.RESET}")
    print(f"{Style.PASS}[ PASS ]{Style.RESET} Complete profile verification alignment with Crossref database records.")
    print(f"{Style.MINOR}[ MINOR]{Style.RESET} High structural confidence pairing with small metadata attribute drifts.")
    print(f"{Style.WARN}[ WARN ]{Style.RESET} Partial structural match or critical explicit tracking identifier divergence.")
    print(f"{Style.GHOST}[GHOST?]{Style.RESET} Title matching overlap below 50%. High probability of generation hallucination.")
    print(f"{Style.FAKE}[ FAKE ]{Style.RESET} Complete lookup resolution failure or expired 404 tracking DOI links.")
    print(f"{Style.SPEC}[ SPEC ]{Style.RESET} Legitimate organizational telecommunications technical specification standard bypass.\n")

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    default_tex = os.path.join(project_root, "main.tex")

    parser = argparse.ArgumentParser(description="Academic Bibliography Citation Metadata Auditor Engine.")
    parser.add_argument('--tex', type=str, default=default_tex, help="Path to absolute target main LaTeX document file.")
    args = parser.parse_args()

    auditor = LatexReferenceAuditor(args.tex)
    citations = auditor.extract_bibitems()
    
    if not citations:
        print(f"{Style.WARN}[WARN] No bibliography entries extracted from document structure.{Style.RESET}")
        sys.exit(0)

    print_legend()
    
    divider = f"{Style.LINE}{'-' * 98}{Style.RESET}"
    print(divider)
    print(f"{Style.INFO}{Style.BOLD}CROSSREF HYBRID METADATA VALIDATOR ENGINE v3.1 (OOP EDITION){Style.RESET}")
    print(divider)
    print(f"TARGET_FILE   : {Style.BOLD}{args.tex}{Style.RESET}")
    print(f"TOTAL_RECS    : {Style.BOLD}{len(citations)}{Style.RESET} entries mapped")
    print(divider)
    
    print(f"{Style.DIM}{'STATUS'.ljust(10)} | {'CITED STRING EXTRACT (TRUNCATED)'.ljust(COL_WIDTH_TITLE)} | RESOLVED DOI / DECISION{Style.RESET}")
    print(divider)
    
    for citation in citations:
        status, metric, details = auditor.verify_citation(citation)
        
        if status == "PASS": status_str = f"{Style.PASS}[ PASS ]{Style.RESET}  "
        elif status == "MINOR": status_str = f"{Style.MINOR}[ MINOR]{Style.RESET}  "
        elif status == "WARN": status_str = f"{Style.WARN}[ WARN ]{Style.RESET}  "
        elif status == "SPEC": status_str = f"{Style.SPEC}[ SPEC ]{Style.RESET}  "
        elif status == "GHOST": status_str = f"{Style.GHOST}[GHOST?]{Style.RESET}  "
        else: status_str = f"{Style.FAKE}[ FAKE ]{Style.RESET}  "

        preview_clean = citation.replace('\n', ' ')
        if len(preview_clean) > COL_WIDTH_TITLE:
            preview_clean = preview_clean[:COL_WIDTH_TITLE - 3] + "..."
        preview_str = preview_clean.ljust(COL_WIDTH_TITLE)

        print(f"{status_str} | {preview_str} | {Style.BOLD}{metric}{Style.RESET}")
        print(f"           {Style.DIM}-> DETAILS: {details}{Style.RESET}")
        time.sleep(0.3)
        
    print(divider)
    print(f"{Style.INFO}Verification pass complete.{Style.RESET}")

if __name__ == "__main__":
    main()