"""
Cybersecurity analysis module for extracting threats, incidents, anomalies, and patterns.
"""

import json
import csv
import re
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


# Common security event patterns
SECURITY_KEYWORDS = {
    'threats': ['malware', 'virus', 'trojan', 'ransomware', 'phishing', 'attack', 'exploit', 'breach', 'intrusion', 'unauthorized'],
    'severity': ['critical', 'high', 'medium', 'low', 'info', 'warning', 'error', 'alert'],
    'incidents': ['incident', 'breach', 'compromise', 'violation', 'policy', 'failed', 'blocked', 'denied'],
    'vulnerabilities': ['vulnerability', 'cve', 'patch', 'update', 'exploit', 'weakness', 'exposure'],
    'authentication': ['login', 'logout', 'auth', 'authentication', 'failed', 'success', 'password', 'credential'],
    'network': ['firewall', 'port', 'ip', 'connection', 'traffic', 'packet', 'ddos', 'scan']
}


def extract_severity(text: str) -> Optional[str]:
    """Extract severity level from text."""
    text_lower = text.lower()
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity in text_lower:
            return severity
    return None


def classify_security_event(text: str, row_data: Dict = None) -> Dict[str, Any]:
    """Classify a security event based on content."""
    text_lower = str(text).lower()
    classification = {
        'type': 'unknown',
        'severity': 'info',
        'keywords_found': [],
        'is_incident': False,
        'is_threat': False
    }
    
    # Check for threat indicators
    for keyword in SECURITY_KEYWORDS['threats']:
        if keyword in text_lower:
            classification['is_threat'] = True
            classification['keywords_found'].append(keyword)
            classification['type'] = 'threat'
    
    # Check for incident indicators
    for keyword in SECURITY_KEYWORDS['incidents']:
        if keyword in text_lower:
            classification['is_incident'] = True
            classification['keywords_found'].append(keyword)
            if classification['type'] == 'unknown':
                classification['type'] = 'incident'
    
    # Extract severity
    severity = extract_severity(text)
    if severity:
        classification['severity'] = severity
    
    # Check for vulnerability indicators
    if any(kw in text_lower for kw in SECURITY_KEYWORDS['vulnerabilities']):
        classification['keywords_found'].extend([kw for kw in SECURITY_KEYWORDS['vulnerabilities'] if kw in text_lower])
        if classification['type'] == 'unknown':
            classification['type'] = 'vulnerability'
    
    return classification


def analyze_csv_security(file_path: Path) -> Dict[str, Any]:
    """Analyze CSV files for security events."""
    incidents = []
    threats = []
    vulnerabilities = []
    severity_counts = Counter()
    event_types = Counter()
    ip_addresses = Counter()
    users = Counter()
    timestamps = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Combine all row values for analysis
                combined_text = ' '.join(str(v) for v in row.values() if v)
                
                classification = classify_security_event(combined_text, row)
                
                # Extract IP addresses
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, combined_text)
                for ip in ips:
                    ip_addresses[ip] += 1
                
                # Extract timestamps
                if 'timestamp' in row or 'time' in row or 'date' in row:
                    ts = row.get('timestamp') or row.get('time') or row.get('date')
                    if ts:
                        timestamps.append(ts)
                
                # Extract usernames
                if 'user' in row or 'username' in row:
                    user = row.get('user') or row.get('username')
                    if user:
                        users[user] += 1
                
                # Categorize events
                severity_counts[classification['severity']] += 1
                event_types[classification['type']] += 1
                
                if classification['is_incident']:
                    incidents.append({
                        'row': row,
                        'classification': classification,
                        'text': combined_text[:200]  # First 200 chars
                    })
                
                if classification['is_threat']:
                    threats.append({
                        'row': row,
                        'classification': classification,
                        'text': combined_text[:200]
                    })
                
                if classification['type'] == 'vulnerability':
                    vulnerabilities.append({
                        'row': row,
                        'classification': classification,
                        'text': combined_text[:200]
                    })
    
    except Exception as e:
        print(f"Error analyzing CSV {file_path}: {e}")
    
    return {
        'incidents': incidents[:50],  # Top 50
        'threats': threats[:50],
        'vulnerabilities': vulnerabilities[:50],
        'severity_counts': dict(severity_counts),
        'event_types': dict(event_types),
        'top_ips': dict(ip_addresses.most_common(20)),
        'top_users': dict(users.most_common(20)),
        'total_events': len(timestamps) if timestamps else 0,
        'date_range': {
            'earliest': min(timestamps) if timestamps else None,
            'latest': max(timestamps) if timestamps else None
        }
    }


def analyze_json_security(file_path: Path) -> Dict[str, Any]:
    """Analyze JSON files for security events."""
    incidents = []
    threats = []
    vulnerabilities = []
    severity_counts = Counter()
    event_types = Counter()
    ip_addresses = Counter()
    users = Counter()
    timestamps = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            data = [data]
        
        for entry in data:
            if not isinstance(entry, dict):
                continue
            
            # Combine all values for analysis
            combined_text = ' '.join(str(v) for v in entry.values() if v)
            
            classification = classify_security_event(combined_text, entry)
            
            # Extract IP addresses
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            for value in entry.values():
                if isinstance(value, str):
                    ips = re.findall(ip_pattern, value)
                    for ip in ips:
                        ip_addresses[ip] += 1
            
            # Extract timestamps
            for key in ['timestamp', 'time', 'date', 'created_at', 'datetime']:
                if key in entry and entry[key]:
                    timestamps.append(str(entry[key]))
                    break
            
            # Extract usernames
            for key in ['user', 'username', 'user_id', 'account']:
                if key in entry and entry[key]:
                    users[str(entry[key])] += 1
                    break
            
            # Categorize events
            severity_counts[classification['severity']] += 1
            event_types[classification['type']] += 1
            
            if classification['is_incident']:
                incidents.append({
                    'entry': entry,
                    'classification': classification
                })
            
            if classification['is_threat']:
                threats.append({
                    'entry': entry,
                    'classification': classification
                })
            
            if classification['type'] == 'vulnerability':
                vulnerabilities.append({
                    'entry': entry,
                    'classification': classification
                })
    
    except Exception as e:
        print(f"Error analyzing JSON {file_path}: {e}")
    
    return {
        'incidents': incidents[:50],
        'threats': threats[:50],
        'vulnerabilities': vulnerabilities[:50],
        'severity_counts': dict(severity_counts),
        'event_types': dict(event_types),
        'top_ips': dict(ip_addresses.most_common(20)),
        'top_users': dict(users.most_common(20)),
        'total_events': len(data),
        'date_range': {
            'earliest': min(timestamps) if timestamps else None,
            'latest': max(timestamps) if timestamps else None
        }
    }


def analyze_text_log_security(file_path: Path) -> Dict[str, Any]:
    """Analyze text log files for security events."""
    incidents = []
    threats = []
    vulnerabilities = []
    severity_counts = Counter()
    event_types = Counter()
    ip_addresses = Counter()
    lines_analyzed = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                lines_analyzed += 1
                line_lower = line.lower()
                
                classification = classify_security_event(line)
                
                # Extract IP addresses
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, line)
                for ip in ips:
                    ip_addresses[ip] += 1
                
                severity_counts[classification['severity']] += 1
                event_types[classification['type']] += 1
                
                if classification['is_incident']:
                    incidents.append({
                        'line': line.strip()[:200],
                        'classification': classification
                    })
                
                if classification['is_threat']:
                    threats.append({
                        'line': line.strip()[:200],
                        'classification': classification
                    })
                
                if classification['type'] == 'vulnerability':
                    vulnerabilities.append({
                        'line': line.strip()[:200],
                        'classification': classification
                    })
    
    except Exception as e:
        print(f"Error analyzing text log {file_path}: {e}")
    
    return {
        'incidents': incidents[:50],
        'threats': threats[:50],
        'vulnerabilities': vulnerabilities[:50],
        'severity_counts': dict(severity_counts),
        'event_types': dict(event_types),
        'top_ips': dict(ip_addresses.most_common(20)),
        'total_events': lines_analyzed
    }


def analyze_all_security_data(cleaned_data_dir: Path, month: str = None) -> Dict[str, Any]:
    """
    Analyze all cleaned security data files.
    
    Returns comprehensive security analysis.
    """
    cleaned_path = cleaned_data_dir
    if month:
        cleaned_path = cleaned_path / month
    
    if not cleaned_path.exists():
        return {}
    
    combined_analysis = {
        'month': month or datetime.now().strftime("%Y-%m"),
        'timestamp': datetime.now().isoformat(),
        'total_incidents': 0,
        'total_threats': 0,
        'total_vulnerabilities': 0,
        'severity_summary': Counter(),
        'event_type_summary': Counter(),
        'top_ips': Counter(),
        'top_users': Counter(),
        'file_analyses': {},
        'key_incidents': [],
        'key_threats': [],
        'trends': {}
    }
    
    for file_path in cleaned_path.iterdir():
        if file_path.is_file() and file_path.name.startswith('cleaned_'):
            file_ext = file_path.suffix.lower()
            
            try:
                if file_ext == '.csv':
                    analysis = analyze_csv_security(file_path)
                elif file_ext == '.json':
                    analysis = analyze_json_security(file_path)
                elif file_ext in ['.txt', '.log']:
                    analysis = analyze_text_log_security(file_path)
                else:
                    continue
                
                combined_analysis['file_analyses'][file_path.name] = analysis
                combined_analysis['total_incidents'] += len(analysis.get('incidents', []))
                combined_analysis['total_threats'] += len(analysis.get('threats', []))
                combined_analysis['total_vulnerabilities'] += len(analysis.get('vulnerabilities', []))
                
                # Aggregate severity counts
                for severity, count in analysis.get('severity_counts', {}).items():
                    combined_analysis['severity_summary'][severity] += count
                
                # Aggregate event types
                for event_type, count in analysis.get('event_types', {}).items():
                    combined_analysis['event_type_summary'][event_type] += count
                
                # Aggregate IPs
                for ip, count in analysis.get('top_ips', {}).items():
                    combined_analysis['top_ips'][ip] += count
                
                # Aggregate users
                for user, count in analysis.get('top_users', {}).items():
                    combined_analysis['top_users'][user] += count
                
                # Collect key incidents and threats
                combined_analysis['key_incidents'].extend(analysis.get('incidents', [])[:10])
                combined_analysis['key_threats'].extend(analysis.get('threats', [])[:10])
            
            except Exception as e:
                print(f"Error processing {file_path.name}: {e}")
    
    # Convert counters to dicts
    combined_analysis['severity_summary'] = dict(combined_analysis['severity_summary'])
    combined_analysis['event_type_summary'] = dict(combined_analysis['event_type_summary'])
    combined_analysis['top_ips'] = dict(combined_analysis['top_ips'].most_common(20))
    combined_analysis['top_users'] = dict(combined_analysis['top_users'].most_common(20))
    
    # Sort key incidents and threats by severity
    combined_analysis['key_incidents'] = sorted(
        combined_analysis['key_incidents'],
        key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(
            x.get('classification', {}).get('severity', 'info')
        )
    )[:20]
    
    combined_analysis['key_threats'] = sorted(
        combined_analysis['key_threats'],
        key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(
            x.get('classification', {}).get('severity', 'info')
        )
    )[:20]
    
    return combined_analysis


if __name__ == "__main__":
    import sys
    
    script_dir = Path(__file__).parent.parent
    cleaned_data = script_dir / "cleaned-data"
    
    month = sys.argv[1] if len(sys.argv) > 1 else datetime.now().strftime("%Y-%m")
    
    analysis = analyze_all_security_data(cleaned_data, month)
    
    # Save analysis
    output_path = cleaned_data.parent / "cleaned-data" / f"security_analysis_{month}.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    
    print(f"Security analysis complete for {month}")
    print(f"Total incidents: {analysis.get('total_incidents', 0)}")
    print(f"Total threats: {analysis.get('total_threats', 0)}")
    print(f"Total vulnerabilities: {analysis.get('total_vulnerabilities', 0)}")
    print(f"Analysis saved to: {output_path}")




