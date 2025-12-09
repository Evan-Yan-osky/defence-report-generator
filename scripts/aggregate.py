"""
Aggregate cleaned data into summary statistics and metrics.
"""

import os
import json
import csv
import glob
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
import statistics

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("Warning: pandas not available. Using basic aggregation.")


def aggregate_csv_data(file_path):
    """Aggregate statistics from CSV files."""
    stats = {
        'total_rows': 0,
        'columns': [],
        'column_stats': {},
        'date_range': None
    }
    
    dates = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        stats['columns'] = reader.fieldnames or []
        
        for row in reader:
            stats['total_rows'] += 1
            
            # Try to extract dates
            for col in stats['columns']:
                if 'date' in col.lower() or 'time' in col.lower():
                    if row.get(col):
                        dates.append(row[col])
            
            # Calculate column statistics
            for col in stats['columns']:
                if col not in stats['column_stats']:
                    stats['column_stats'][col] = {
                        'non_empty': 0,
                        'unique_values': set()
                    }
                
                value = row.get(col, '').strip()
                if value:
                    stats['column_stats'][col]['non_empty'] += 1
                    stats['column_stats'][col]['unique_values'].add(value)
    
    # Convert sets to counts
    for col in stats['column_stats']:
        stats['column_stats'][col]['unique_count'] = len(stats['column_stats'][col]['unique_values'])
        stats['column_stats'][col]['unique_values'] = list(stats['column_stats'][col]['unique_values'])[:10]  # Keep first 10
    
    if dates:
        stats['date_range'] = {
            'earliest': min(dates),
            'latest': max(dates)
        }
    
    return stats


def aggregate_json_data(file_path):
    """Aggregate statistics from JSON files."""
    stats = {
        'total_entries': 0,
        'keys': [],
        'key_stats': {},
        'structure': 'unknown'
    }
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        stats['structure'] = 'array'
        stats['total_entries'] = len(data)
        
        if data and isinstance(data[0], dict):
            stats['keys'] = list(data[0].keys())
            
            for entry in data:
                for key in stats['keys']:
                    if key not in stats['key_stats']:
                        stats['key_stats'][key] = {
                            'count': 0,
                            'types': Counter(),
                            'sample_values': []
                        }
                    
                    value = entry.get(key)
                    if value is not None:
                        stats['key_stats'][key]['count'] += 1
                        stats['key_stats'][key]['types'][type(value).__name__] += 1
                        if len(stats['key_stats'][key]['sample_values']) < 5:
                            stats['key_stats'][key]['sample_values'].append(str(value)[:50])
    
    elif isinstance(data, dict):
        stats['structure'] = 'object'
        stats['total_entries'] = 1
        stats['keys'] = list(data.keys())
    
    return stats


def aggregate_all(cleaned_data_dir, month=None):
    """
    Aggregate all cleaned data files.
    
    Args:
        cleaned_data_dir: Path to cleaned data directory
        month: Optional month identifier
    """
    cleaned_path = Path(cleaned_data_dir)
    
    if month:
        cleaned_path = cleaned_path / month
    
    if not cleaned_path.exists():
        print(f"Cleaned data directory not found: {cleaned_path}")
        return None
    
    # Try pandas-based aggregation for CSV files first
    if PANDAS_AVAILABLE:
        csv_files = list(cleaned_path.glob("cleaned_*.csv"))
        if csv_files:
            try:
                all_dfs = []
                for f in csv_files:
                    try:
                        # Try UTF-8 first, fallback to latin-1 if encoding issues
                        try:
                            df = pd.read_csv(f, encoding='utf-8')
                        except UnicodeDecodeError:
                            df = pd.read_csv(f, encoding='latin-1')
                        all_dfs.append(df)
                    except Exception as e:
                        print(f"Error reading {f.name}: {e}")
                
                if all_dfs:
                    aggregated_df = pd.concat(all_dfs, ignore_index=True)
                    aggregated_csv_path = cleaned_path / "aggregated.csv"
                    aggregated_df.to_csv(aggregated_csv_path, index=False)
                    print(f"Aggregated {len(all_dfs)} CSV files into {aggregated_csv_path}")
                    print(f"Total rows in aggregated CSV: {len(aggregated_df)}")
            except Exception as e:
                print(f"Error with pandas aggregation: {e}")
                # Fall through to basic aggregation
    
    # Continue with detailed aggregation for statistics
    aggregated = {
        'month': month or datetime.now().strftime("%Y-%m"),
        'timestamp': datetime.now().isoformat(),
        'files': {},
        'summary': {
            'total_files': 0,
            'total_csv_rows': 0,
            'total_json_entries': 0
        }
    }
    
    for file_path in cleaned_path.iterdir():
        if file_path.is_file() and file_path.name.startswith('cleaned_'):
            file_ext = file_path.suffix.lower()
            
            try:
                if file_ext == '.csv':
                    stats = aggregate_csv_data(file_path)
                    aggregated['files'][file_path.name] = stats
                    aggregated['summary']['total_csv_rows'] += stats['total_rows']
                elif file_ext == '.json':
                    stats = aggregate_json_data(file_path)
                    aggregated['files'][file_path.name] = stats
                    aggregated['summary']['total_json_entries'] += stats['total_entries']
                
                aggregated['summary']['total_files'] += 1
            except Exception as e:
                print(f"Error aggregating {file_path.name}: {e}")
    
    # Save aggregated data as JSON
    output_path = cleaned_path.parent / f"aggregated_{month or datetime.now().strftime('%Y-%m')}.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(aggregated, f, indent=2, ensure_ascii=False)
    
    print(f"Aggregation complete. Summary: {aggregated['summary']}")
    print(f"Saved to: {output_path}")
    
    return aggregated


if __name__ == "__main__":
    import sys
    
    # Default paths
    script_dir = Path(__file__).parent.parent
    cleaned_data = script_dir / "cleaned-data"
    
    # Get month from command line or use current month
    month = sys.argv[1] if len(sys.argv) > 1 else datetime.now().strftime("%Y-%m")
    
    aggregate_all(cleaned_data, month)

