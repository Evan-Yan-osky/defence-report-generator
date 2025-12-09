"""
Compare data and metrics across different months.
"""

import json
import glob
from pathlib import Path
from datetime import datetime
from collections import defaultdict

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("Warning: pandas not available. Using basic comparison.")


def load_aggregated_data(cleaned_data_dir, month):
    """Load aggregated data for a specific month."""
    aggregated_path = Path(cleaned_data_dir).parent / "cleaned-data" / f"aggregated_{month}.json"
    
    if not aggregated_path.exists():
        return None
    
    with open(aggregated_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def compare_months_csv(history_dir, cleaned_data_dir):
    """
    Compare months using pandas-based CSV comparison.
    Compares the two most recent aggregated CSV files.
    
    Args:
        history_dir: Path to history directory
        cleaned_data_dir: Path to cleaned data directory
    """
    if not PANDAS_AVAILABLE:
        return None
    
    # Look for aggregated CSV files in history or cleaned-data
    history_files = sorted(glob.glob(str(Path(history_dir) / "*.csv")))
    cleaned_files = sorted(glob.glob(str(Path(cleaned_data_dir) / "aggregated.csv")))
    
    # Combine both locations
    all_csv_files = sorted(set(history_files + cleaned_files))
    
    if len(all_csv_files) < 2:
        print("Not enough months of history for CSV comparison.")
        return None
    
    try:
        current = pd.read_csv(all_csv_files[-1])
        previous = pd.read_csv(all_csv_files[-2])
        
        summary = {
            "alerts_change": len(current) - len(previous),
            "critical_diff": sum(current["severity"] == "critical") - 
                            sum(previous["severity"] == "critical"),
        }
        
        # Add more detailed comparisons if columns exist
        if "severity" in current.columns and "severity" in previous.columns:
            for severity in ["high", "medium", "low"]:
                if severity in current["severity"].values or severity in previous["severity"].values:
                    summary[f"{severity}_diff"] = sum(current["severity"] == severity) - \
                                                  sum(previous["severity"] == severity)
        
        # Save comparison summary
        output_path = Path(cleaned_data_dir) / "comparison_summary.csv"
        pd.DataFrame([summary]).to_csv(output_path, index=False)
        print(f"Comparison summary generated: {output_path}")
        
        return summary
    except Exception as e:
        print(f"Error in CSV comparison: {e}")
        return None


def compare_months(month1, month2, cleaned_data_dir):
    """
    Compare two months of aggregated data.
    
    Args:
        month1: First month (YYYY-MM format)
        month2: Second month (YYYY-MM format)
        cleaned_data_dir: Path to cleaned data directory
    """
    data1 = load_aggregated_data(cleaned_data_dir, month1)
    data2 = load_aggregated_data(cleaned_data_dir, month2)
    
    if not data1:
        print(f"Data not found for {month1}")
        return None
    
    if not data2:
        print(f"Data not found for {month2}")
        return None
    
    comparison = {
        'month1': month1,
        'month2': month2,
        'comparison_date': datetime.now().isoformat(),
        'summary_changes': {},
        'file_changes': {}
    }
    
    # Compare summary statistics
    summary1 = data1.get('summary', {})
    summary2 = data2.get('summary', {})
    
    for key in set(list(summary1.keys()) + list(summary2.keys())):
        val1 = summary1.get(key, 0)
        val2 = summary2.get(key, 0)
        diff = val2 - val1
        pct_change = ((val2 - val1) / val1 * 100) if val1 > 0 else (100 if val2 > 0 else 0)
        
        comparison['summary_changes'][key] = {
            month1: val1,
            month2: val2,
            'difference': diff,
            'percent_change': round(pct_change, 2)
        }
    
    # Compare file-level statistics
    files1 = data1.get('files', {})
    files2 = data2.get('files', {})
    
    all_files = set(list(files1.keys()) + list(files2.keys()))
    
    for filename in all_files:
        file1_data = files1.get(filename, {})
        file2_data = files2.get(filename, {})
        
        file_comparison = {
            'exists_in_month1': filename in files1,
            'exists_in_month2': filename in files2,
            'changes': {}
        }
        
        # Compare common metrics
        if 'total_rows' in file1_data or 'total_rows' in file2_data:
            rows1 = file1_data.get('total_rows', 0)
            rows2 = file2_data.get('total_rows', 0)
            file_comparison['changes']['total_rows'] = {
                month1: rows1,
                month2: rows2,
                'difference': rows2 - rows1
            }
        
        if 'total_entries' in file1_data or 'total_entries' in file2_data:
            entries1 = file1_data.get('total_entries', 0)
            entries2 = file2_data.get('total_entries', 0)
            file_comparison['changes']['total_entries'] = {
                month1: entries1,
                month2: entries2,
                'difference': entries2 - entries1
            }
        
        comparison['file_changes'][filename] = file_comparison
    
    return comparison


def generate_comparison_report(comparison, output_path):
    """Generate a human-readable comparison report."""
    report_lines = [
        f"# Monthly Comparison Report",
        f"",
        f"**Comparing:** {comparison['month1']} vs {comparison['month2']}",
        f"**Generated:** {comparison['comparison_date']}",
        f"",
        f"## Summary Changes",
        f""
    ]
    
    for metric, change_data in comparison['summary_changes'].items():
        report_lines.append(f"### {metric.replace('_', ' ').title()}")
        report_lines.append(f"- {comparison['month1']}: {change_data[comparison['month1']]}")
        report_lines.append(f"- {comparison['month2']}: {change_data[comparison['month2']]}")
        report_lines.append(f"- **Difference:** {change_data['difference']} ({change_data['percent_change']}%)")
        report_lines.append("")
    
    report_lines.append("## File-Level Changes\n")
    
    for filename, file_data in comparison['file_changes'].items():
        report_lines.append(f"### {filename}")
        report_lines.append(f"- Present in {comparison['month1']}: {file_data['exists_in_month1']}")
        report_lines.append(f"- Present in {comparison['month2']}: {file_data['exists_in_month2']}")
        
        if file_data['changes']:
            report_lines.append("\n**Changes:**")
            for change_type, change_info in file_data['changes'].items():
                report_lines.append(f"- {change_type}: {change_info['difference']} ({change_info[comparison['month1']]} → {change_info[comparison['month2']]})")
        report_lines.append("")
    
    report_content = "\n".join(report_lines)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    print(f"Comparison report saved to: {output_path}")
    return report_content


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: compare_months.py <month1> <month2>")
        print("Example: compare_months.py 2024-10 2024-11")
        sys.exit(1)
    
    month1 = sys.argv[1]
    month2 = sys.argv[2]
    
    script_dir = Path(__file__).parent.parent
    cleaned_data = script_dir / "cleaned-data"
    
    comparison = compare_months(month1, month2, cleaned_data)
    
    if comparison:
        output_path = script_dir / "history" / f"comparison_{month1}_vs_{month2}.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        generate_comparison_report(comparison, output_path)
        
        # Also save JSON version
        json_path = script_dir / "history" / f"comparison_{month1}_vs_{month2}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False)
        
        print(f"Comparison data saved to: {json_path}")

