"""
Main script to generate Monthly Cybersecurity Reports.
This script orchestrates the entire cybersecurity report generation process:
1. Clean raw security data
2. Aggregate cleaned data
3. Analyze security events (threats, incidents, vulnerabilities)
4. Compare with previous month (if available)
5. Read previous month's report
6. Generate comprehensive cybersecurity report
"""

import sys
import json
import re
from pathlib import Path
from datetime import datetime
from collections import Counter


# Add scripts directory to path
scripts_dir = Path(__file__).parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from clean_logs import clean_logs
from aggregate import aggregate_all
from compare_months import compare_months, generate_comparison_report
from analyze_security import analyze_all_security_data


def get_previous_month(current_month):
    """Get the previous month in YYYY-MM format."""
    year, month = map(int, current_month.split('-'))
    if month == 1:
        return f"{year-1}-12"
    else:
        return f"{year}-{month-1:02d}"


def load_previous_report(history_dir, prev_month):
    """Load and parse the previous month's report if it exists."""
    report_path = history_dir / f"report_{prev_month}.md"
    
    if not report_path.exists():
        return None
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract key metrics from previous report
        prev_data = {
            'content': content,
            'incidents': 0,
            'threats': 0,
            'vulnerabilities': 0,
            'severity_breakdown': {}
        }
        
        # Try to extract numbers from the report
        incident_match = re.search(r'(\d+)\s*(?:total\s*)?incidents?', content, re.IGNORECASE)
        if incident_match:
            prev_data['incidents'] = int(incident_match.group(1))
        
        threat_match = re.search(r'(\d+)\s*(?:total\s*)?threats?', content, re.IGNORECASE)
        if threat_match:
            prev_data['threats'] = int(threat_match.group(1))
        
        vuln_match = re.search(r'(\d+)\s*(?:total\s*)?vulnerabilit(?:ies|y)', content, re.IGNORECASE)
        if vuln_match:
            prev_data['vulnerabilities'] = int(vuln_match.group(1))
        
        return prev_data
    except Exception as e:
        print(f"Warning: Could not parse previous report: {e}")
        return None


def generate_cybersecurity_report(month, aggregated_data, security_analysis, comparison_data=None, prev_report=None):
    """Generate comprehensive cybersecurity report content using the template format."""
    
    # Calculate risk level
    total_incidents = security_analysis.get('total_incidents', 0)
    total_threats = security_analysis.get('total_threats', 0)
    total_vulns = security_analysis.get('total_vulnerabilities', 0)
    severity = security_analysis.get('severity_summary', {})
    critical_count = severity.get('critical', 0) + severity.get('high', 0)
    
    if critical_count > 10:
        risk_level = "HIGH"
    elif critical_count > 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    # Build sections
    summary = build_executive_summary(month, total_incidents, total_threats, total_vulns, critical_count, risk_level)
    incidents_table = build_incident_overview(security_analysis, total_incidents)
    alert_trends = build_alert_trends(security_analysis)
    system_health = build_system_health(aggregated_data, security_analysis, total_vulns, total_events=sum(severity.values()))
    threat_intel = build_threat_intelligence(security_analysis, total_threats)
    recommendations = build_recommendations(critical_count, total_incidents, total_vulns, security_analysis.get('top_ips', {}))
    comparison = build_month_comparison(month, total_incidents, total_threats, total_vulns, comparison_data, prev_report)
    data_tables = build_data_tables(security_analysis, total_incidents, total_threats, total_vulns, critical_count)
    graphs = build_graph_descriptions(month, security_analysis, total_events=sum(severity.values()))
    
    # Build report using template format
    report_content = f"""# Monthly Cybersecurity Report – {month}

## 1. Executive Summary

{summary}

## 2. Incident Overview

| Incident | Severity | Date | Status | Summary |
|----------|----------|------|--------|---------|
{incidents_table}

## 3. Alert Trends

{alert_trends}

## 4. System Health & Vulnerabilities

{system_health}

## 5. Threat Intelligence Overview

{threat_intel}

## 6. Recommendations

{recommendations}

## 7. Month-to-Month Comparison

{comparison}

## 8. Data Tables

{data_tables}

## 9. Graph Descriptions

{graphs}
"""
    
    return report_content


def build_executive_summary(month, total_incidents, total_threats, total_vulns, critical_count, risk_level):
    """Build executive summary section."""
    summary_lines = [
        f"This monthly cybersecurity report provides a comprehensive analysis of security events, incidents, and threats "
        f"identified during {month}.",
        "",
        f"**Key Highlights:**",
        f"- **Total Incidents:** {total_incidents}",
        f"- **Total Threats Detected:** {total_threats}",
        f"- **Vulnerabilities Identified:** {total_vulns}",
        f"- **Critical/High Severity Events:** {critical_count}",
        f"- **Overall Risk Assessment:** {risk_level}",
        "",
    ]
    
    # Add narrative summary
    if total_incidents > 0:
        summary_lines.append(f"During this reporting period, {total_incidents} security incident(s) were identified and analyzed.")
    if critical_count > 0:
        summary_lines.append(f"{critical_count} critical or high-severity security events require immediate attention.")
    if total_threats > 0:
        summary_lines.append(f"The security monitoring systems detected {total_threats} potential threat(s) that were investigated.")
    
    summary_lines.append("")
    summary_lines.append("**Critical Action Items:**")
    
    if critical_count > 0:
        summary_lines.append(f"- Address {critical_count} critical/high-severity security events immediately")
    if total_vulns > 0:
        summary_lines.append(f"- Remediate {total_vulns} identified vulnerability/vulnerabilities")
    if total_incidents > 0:
        summary_lines.append(f"- Review and document {total_incidents} security incident(s)")
    
    return "\n".join(summary_lines)


def build_incident_overview(security_analysis, total_incidents):
    """Build incident overview table."""
    key_incidents = security_analysis.get('key_incidents', [])[:20]
    
    if not key_incidents:
        return "No significant security incidents were identified during this reporting period."
    
    table_rows = []
    for idx, incident in enumerate(key_incidents, 1):
        classification = incident.get('classification', {})
        severity = classification.get('severity', 'unknown').upper()
        event_type = classification.get('type', 'unknown')
        keywords = ', '.join(classification.get('keywords_found', [])[:3]) if classification.get('keywords_found') else 'N/A'
        
        # Extract date/timestamp
        date = "N/A"
        if 'row' in incident:
            row = incident.get('row', {})
            date = row.get('timestamp') or row.get('time') or row.get('date', 'N/A')
        elif 'entry' in incident:
            entry = incident.get('entry', {})
            date = entry.get('timestamp') or entry.get('time') or entry.get('date', 'N/A')
        
        # Extract summary
        summary = keywords
        if 'row' in incident:
            row_text = ' '.join(str(v) for v in incident.get('row', {}).values() if v)[:100]
            if row_text:
                summary = row_text
        elif 'entry' in incident:
            entry_text = ' '.join(str(v) for v in incident.get('entry', {}).values() if v)[:100]
            if entry_text:
                summary = entry_text
        elif 'line' in incident:
            summary = incident.get('line', '')[:100]
        
        # Status (default to "Under Investigation" for incidents)
        status = "Under Investigation"
        
        table_rows.append(f"| Incident #{idx} | {severity} | {date} | {status} | {summary[:80]}... |")
    
    return "\n".join(table_rows) if table_rows else "No incidents recorded."


def build_alert_trends(security_analysis):
    """Build alert trends section."""
    severity_summary = security_analysis.get('severity_summary', {})
    event_type_summary = security_analysis.get('event_type_summary', {})
    total_events = sum(severity_summary.values())
    top_ips = security_analysis.get('top_ips', {})
    top_users = security_analysis.get('top_users', {})
    
    lines = [
        "### Security Event Trends",
        "",
        "**Security Events by Severity:**",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_summary.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.upper()} | {count} |")
    
    lines.extend([
        "",
        "**Event Types:**",
        "",
        "| Event Type | Count |",
        "|------------|-------|",
    ])
    
    for event_type, count in sorted(event_type_summary.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            lines.append(f"| {event_type.title()} | {count} |")
    
    lines.extend([
        "",
        "### Alert Analysis",
        "",
        f"- **Total Security Events:** {total_events}",
        f"- **Alert Volume:** {total_events} alerts processed",
    ])
    
    if severity_summary:
        peak_sev = max(severity_summary.items(), key=lambda x: x[1])[0]
        lines.append(f"- **Peak Severity:** {peak_sev.upper()}")
    
    if top_ips:
        lines.extend([
            "",
            "**Top Threat Sources (IP Addresses):**",
            "",
            "| IP Address | Event Count |",
            "|------------|-------------|",
        ])
        for ip, count in list(top_ips.items())[:10]:
            lines.append(f"| {ip} | {count} |")
    
    if top_users:
        lines.extend([
            "",
            "**Top Active Users:**",
            "",
            "| Username | Activity Count |",
            "|----------|----------------|",
        ])
        for user, count in list(top_users.items())[:10]:
            lines.append(f"| {user} | {count} |")
    
    return "\n".join(lines)


def build_system_health(aggregated_data, security_analysis, total_vulns, total_events):
    """Build system health and vulnerabilities section."""
    vulnerabilities = security_analysis.get('vulnerabilities', [])
    
    lines = [
        "### Vulnerability Summary",
        "",
    ]
    
    if vulnerabilities:
        vuln_by_severity = Counter()
        for vuln in vulnerabilities:
            sev = vuln.get('classification', {}).get('severity', 'unknown')
            vuln_by_severity[sev] += 1
        
        lines.extend([
            f"**Total Vulnerabilities:** {total_vulns}",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ])
        
        for sev in ['critical', 'high', 'medium', 'low']:
            count = vuln_by_severity.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")
        
        lines.extend([
            "",
            "**Key Vulnerabilities:**",
            "",
        ])
        
        for idx, vuln in enumerate(vulnerabilities[:5], 1):
            classification = vuln.get('classification', {})
            severity = classification.get('severity', 'unknown').upper()
            keywords = ', '.join(classification.get('keywords_found', [])[:3]) if classification.get('keywords_found') else 'Vulnerability detected'
            lines.append(f"{idx}. **{severity}** - {keywords}")
    else:
        lines.append("No vulnerabilities were identified in the analyzed data during this period.")
    
    lines.extend([
        "",
        "### System Health Metrics",
        "",
        f"- **Data Sources Analyzed:** {len(aggregated_data.get('files', {}))}",
        f"- **Total Events Processed:** {total_events}",
        f"- **Security Monitoring Status:** Active",
    ])
    
    return "\n".join(lines)


def build_threat_intelligence(security_analysis, total_threats):
    """Build threat intelligence overview section."""
    key_threats = security_analysis.get('key_threats', [])[:10]
    
    lines = [
        "### Threat Landscape",
        "",
    ]
    
    if key_threats:
        lines.append(f"**Threats Detected:** {total_threats}")
        lines.append("")
        lines.append("**Top Threats Identified:**")
        lines.append("")
        
        threat_types = Counter()
        for threat in key_threats:
            keywords = threat.get('classification', {}).get('keywords_found', [])
            for kw in keywords:
                threat_types[kw] += 1
        
        lines.extend([
            "| Threat Type | Frequency |",
            "|-------------|-----------|",
        ])
        for threat_type, count in threat_types.most_common(10):
            lines.append(f"| {threat_type.title()} | {count} |")
    else:
        lines.append("No significant external threats were identified in the analyzed data.")
    
    lines.extend([
        "",
        "### External Risk Assessment",
        "",
        "- **External Threat Monitoring:** Active",
        "- **Third-Party Risk Assessment:** Review recommended",
        "- **Supply Chain Security:** Monitor ongoing",
    ])
    
    return "\n".join(lines)


def build_recommendations(critical_count, total_incidents, total_vulns, top_ips):
    """Build recommendations section."""
    lines = [
        "### Immediate Actions (Priority: High)",
        "",
    ]
    
    immediate_actions = []
    
    if critical_count > 0:
        immediate_actions.append(f"- **URGENT:** Address {critical_count} critical/high-severity security events immediately")
    if total_incidents > 0:
        immediate_actions.append(f"- Investigate and document all {total_incidents} security incident(s)")
    if total_vulns > 0:
        immediate_actions.append(f"- Prioritize remediation of {total_vulns} identified vulnerability/vulnerabilities")
    if top_ips:
        top_threat_ip = list(top_ips.keys())[0]
        immediate_actions.append(f"- Review and potentially block suspicious IP: {top_threat_ip} ({top_ips[top_threat_ip]} events)")
    
    if immediate_actions:
        lines.extend(immediate_actions)
    else:
        lines.append("- Continue monitoring security events")
        lines.append("- Maintain current security posture")
    
    lines.extend([
        "",
        "### Strategic Recommendations (Priority: Medium/Low)",
        "",
        "- Enhance security monitoring and alerting capabilities",
        "- Implement regular vulnerability scanning and assessment",
        "- Conduct security awareness training for staff",
        "- Review and update security policies and procedures",
        "- Consider implementing additional threat intelligence feeds",
    ])
    
    return "\n".join(lines)


def build_month_comparison(month, total_incidents, total_threats, total_vulns, comparison_data, prev_report):
    """Build month-to-month comparison section."""
    prev_month = get_previous_month(month)
    lines = []
    
    if comparison_data or prev_report:
        lines.append(f"**Comparison Period:** {prev_month} vs {month}")
        lines.append("")
        
        if prev_report:
            prev_incidents = prev_report.get('incidents', 0)
            prev_threats = prev_report.get('threats', 0)
            prev_vulns = prev_report.get('vulnerabilities', 0)
            
            lines.extend([
                "### Security Metrics Comparison",
                "",
                "| Metric | Previous Month | Current Month | Change |",
                "|--------|----------------|---------------|--------|",
            ])
            
            # Incidents comparison
            incident_change = total_incidents - prev_incidents
            incident_pct = ((total_incidents - prev_incidents) / prev_incidents * 100) if prev_incidents > 0 else (100 if total_incidents > 0 else 0)
            lines.append(f"| Incidents | {prev_incidents} | {total_incidents} | {incident_change:+d} ({incident_pct:+.1f}%) |")
            
            # Threats comparison
            threat_change = total_threats - prev_threats
            threat_pct = ((total_threats - prev_threats) / prev_threats * 100) if prev_threats > 0 else (100 if total_threats > 0 else 0)
            lines.append(f"| Threats | {prev_threats} | {total_threats} | {threat_change:+d} ({threat_pct:+.1f}%) |")
            
            # Vulnerabilities comparison
            vuln_change = total_vulns - prev_vulns
            vuln_pct = ((total_vulns - prev_vulns) / prev_vulns * 100) if prev_vulns > 0 else (100 if total_vulns > 0 else 0)
            lines.append(f"| Vulnerabilities | {prev_vulns} | {total_vulns} | {vuln_change:+d} ({vuln_pct:+.1f}%) |")
            
            lines.append("")
        
        if comparison_data:
            lines.append("### Data Volume Comparison")
            lines.append("")
            for metric, change_data in list(comparison_data.get('summary_changes', {}).items())[:5]:
                lines.append(f"- **{metric.replace('_', ' ').title()}:** {change_data.get('difference', 0):+d} ({change_data.get('percent_change', 0):+.1f}%)")
    else:
        lines.append(f"No previous month data available for comparison. This appears to be the first report.")
    
    return "\n".join(lines)


def build_data_tables(security_analysis, total_incidents, total_threats, total_vulns, critical_count):
    """Build data tables section."""
    severity_summary = security_analysis.get('severity_summary', {})
    total_events = sum(severity_summary.values())
    
    lines = [
        "### Security Event Summary",
        "",
        "| Category | Count |",
        "|----------|-------|",
        f"| Total Incidents | {total_incidents} |",
        f"| Total Threats | {total_threats} |",
        f"| Total Vulnerabilities | {total_vulns} |",
        f"| Total Security Events | {total_events} |",
        f"| Critical/High Severity | {critical_count} |",
        "",
        "### Severity Breakdown",
        "",
        "| Severity | Count | Percentage |",
        "|----------|-------|------------|",
    ]
    
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_summary.get(sev, 0)
        pct = (count / total_events * 100) if total_events > 0 else 0
        if count > 0:
            lines.append(f"| {sev.upper()} | {count} | {pct:.1f}% |")
    
    return "\n".join(lines)


def build_graph_descriptions(month, security_analysis, total_events):
    """Build graph descriptions section."""
    top_ips = security_analysis.get('top_ips', {})
    
    lines = [
        "### [Graph 1]: Security Events Over Time",
        f"Line chart showing the daily/weekly distribution of security events throughout {month}. ",
        f"X-axis: Time period, Y-axis: Number of events. ",
        f"Use different colors for different severity levels.",
        "",
        "### [Graph 2]: Severity Distribution",
        f"Pie chart displaying the proportion of security events by severity level. ",
        f"Segments: Critical, High, Medium, Low, Info. ",
        f"Total events: {total_events}.",
        "",
        "### [Graph 3]: Top 10 Threat Sources",
        f"Bar chart showing the IP addresses or sources with the highest number of security events. ",
        f"X-axis: IP Address/Source, Y-axis: Event count. ",
        f"Data: {dict(list(top_ips.items())[:10]) if top_ips else 'No data available'}.",
        "",
        "### [Graph 4]: Incident Timeline",
        f"Timeline chart displaying when security incidents occurred during {month}. ",
        f"X-axis: Date/Time, Y-axis: Incident severity. ",
        f"Use markers of different sizes/colors to represent severity levels.",
        "",
        "### [Graph 5]: Vulnerability Trend",
        f"Area chart showing the accumulation of vulnerabilities over time. ",
        f"X-axis: Time period, Y-axis: Cumulative vulnerability count. ",
        f"Stack different severity levels to show composition.",
    ]
    
    return "\n".join(lines)
    


def main():
    """Main function to orchestrate cybersecurity report generation."""
    # Get month from command line or use current month
    if len(sys.argv) > 1:
        month = sys.argv[1]
        # Validate format
        try:
            datetime.strptime(month, "%Y-%m")
        except ValueError:
            print(f"Invalid month format: {month}. Use YYYY-MM format (e.g., 2024-11)")
            sys.exit(1)
    else:
        month = datetime.now().strftime("%Y-%m")
    
    print(f"Generating Monthly Cybersecurity Report for {month}...")
    print("=" * 60)
    
    # Setup paths
    base_dir = Path(__file__).parent
    raw_data_dir = base_dir / "raw-data"
    cleaned_data_dir = base_dir / "cleaned-data"
    history_dir = base_dir / "history"
    
    # Ensure directories exist
    history_dir.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Clean raw data
    print("\n[Step 1/5] Cleaning raw security data...")
    try:
        clean_logs(raw_data_dir, cleaned_data_dir, month)
        print("✓ Data cleaning complete")
    except Exception as e:
        print(f"✗ Error during cleaning: {e}")
        return
    
    # Step 2: Aggregate cleaned data
    print("\n[Step 2/5] Aggregating cleaned data...")
    try:
        aggregated_data = aggregate_all(cleaned_data_dir, month)
        if not aggregated_data:
            print("✗ No data to aggregate")
            return
        print("✓ Data aggregation complete")
    except Exception as e:
        print(f"✗ Error during aggregation: {e}")
        return
    
    # Step 3: Analyze security data
    print("\n[Step 3/5] Analyzing security events, threats, and incidents...")
    try:
        security_analysis = analyze_all_security_data(cleaned_data_dir, month)
        if not security_analysis:
            print("⚠ No security analysis data generated")
            security_analysis = {}
        else:
            print(f"✓ Security analysis complete")
            print(f"  - Incidents: {security_analysis.get('total_incidents', 0)}")
            print(f"  - Threats: {security_analysis.get('total_threats', 0)}")
            print(f"  - Vulnerabilities: {security_analysis.get('total_vulnerabilities', 0)}")
    except Exception as e:
        print(f"✗ Error during security analysis: {e}")
        security_analysis = {}
    
    # Step 4: Load previous report and compare
    print("\n[Step 4/5] Loading previous month's report and comparing...")
    prev_month = get_previous_month(month)
    prev_report = load_previous_report(history_dir, prev_month)
    comparison_data = None
    
    # Try pandas-based CSV comparison
    try:
        # Import the function dynamically
        import importlib.util
        compare_module_path = scripts_dir / "compare_months.py"
        if compare_module_path.exists():
            spec = importlib.util.spec_from_file_location("compare_months", compare_module_path)
            compare_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(compare_module)
            if hasattr(compare_module, 'compare_months_csv'):
                csv_summary = compare_module.compare_months_csv(history_dir, cleaned_data_dir)
                if csv_summary:
                    print(f"✓ CSV comparison complete (alerts_change: {csv_summary.get('alerts_change', 0)}, critical_diff: {csv_summary.get('critical_diff', 0)})")
    except Exception as e:
        print(f"⚠ Error during CSV comparison: {e}")
    
    # Also do detailed JSON-based comparison if available
    prev_aggregated_path = cleaned_data_dir / f"aggregated_{prev_month}.json"
    if prev_aggregated_path.exists():
        try:
            comparison_data = compare_months(prev_month, month, cleaned_data_dir)
            if comparison_data:
                comparison_report_path = history_dir / f"comparison_{prev_month}_vs_{month}.md"
                generate_comparison_report(comparison_data, comparison_report_path)
                print(f"✓ Detailed comparison complete")
        except Exception as e:
            print(f"⚠ Error during detailed comparison: {e}")
    
    if prev_report:
        print(f"✓ Previous report loaded ({prev_month})")
    else:
        print(f"⚠ Previous report not found ({prev_month})")
    
    # Step 5: Generate final cybersecurity report
    print("\n[Step 5/5] Generating comprehensive cybersecurity report...")
    try:
        report_content = generate_cybersecurity_report(
            month, aggregated_data, security_analysis, comparison_data, prev_report
        )
        
        # Save report
        report_path = history_dir / f"report_{month}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"✓ Cybersecurity report generated successfully!")
        print(f"  Saved to: {report_path}")
        
        # Save security analysis for reference
        security_analysis_path = history_dir / f"security_analysis_{month}.json"
        with open(security_analysis_path, 'w', encoding='utf-8') as f:
            json.dump(security_analysis, f, indent=2, ensure_ascii=False)
        
        print(f"  Security analysis saved to: {security_analysis_path}")
        
    except Exception as e:
        print(f"✗ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n" + "=" * 60)
    print("Cybersecurity Report Generation Complete!")
    print(f"\nReport Summary:")
    print(f"  - Incidents: {security_analysis.get('total_incidents', 0)}")
    print(f"  - Threats: {security_analysis.get('total_threats', 0)}")
    print(f"  - Vulnerabilities: {security_analysis.get('total_vulnerabilities', 0)}")
    print(f"\nNext steps:")
    print(f"1. Review the report: {report_path}")
    if comparison_data:
        print(f"2. Check comparison details: {history_dir / f'comparison_{prev_month}_vs_{month}.md'}")
    print(f"3. Add raw security data for next month to: {raw_data_dir}")


if __name__ == "__main__":
    main()
