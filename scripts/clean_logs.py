"""
Clean and preprocess log files for monthly reports.
Handles various log formats (CSV, JSON, text logs).
"""

import os
import json
import csv
import re
import glob
from datetime import datetime
from pathlib import Path

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("Warning: pandas not available. Using basic CSV cleaning.")


def clean_df(df):
    """Clean DataFrame by filtering severity levels."""
    if "severity" in df.columns:
        df = df[df["severity"].isin(["medium", "high", "critical"])]
    return df


def clean_csv_log(file_path, output_path):
    """Clean CSV log files using pandas if available, otherwise use basic cleaning."""
    if PANDAS_AVAILABLE:
        try:
            # Use pandas-based cleaning
            # Note: pandas read_csv handles encoding errors automatically
            # For older pandas versions, we'll catch encoding errors and retry with different encoding
            try:
                df = pd.read_csv(file_path, encoding='utf-8')
            except UnicodeDecodeError:
                # Fallback to latin-1 which can read any byte sequence
                df = pd.read_csv(file_path, encoding='latin-1')
            df = clean_df(df)
            
            # Remove duplicates
            df = df.drop_duplicates()
            
            # Save cleaned data
            df.to_csv(output_path, index=False, encoding='utf-8')
            return len(df)
        except Exception as e:
            print(f"Error with pandas cleaning, falling back to basic method: {e}")
            # Fall through to basic cleaning
    
    # Basic CSV cleaning (fallback or when pandas not available)
    cleaned_rows = []
    seen = set()
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Filter by severity if column exists
            if 'severity' in row:
                severity = str(row.get('severity', '')).lower().strip()
                if severity not in ['medium', 'high', 'critical']:
                    continue
            
            # Create a hash of the row to detect duplicates
            row_hash = hash(tuple(sorted(row.items())))
            if row_hash not in seen:
                # Remove empty values and trim whitespace
                cleaned_row = {k: v.strip() if v else '' for k, v in row.items()}
                if any(cleaned_row.values()):  # Only add non-empty rows
                    cleaned_rows.append(cleaned_row)
                    seen.add(row_hash)
    
    if cleaned_rows:
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=cleaned_rows[0].keys())
            writer.writeheader()
            writer.writerows(cleaned_rows)
    
    return len(cleaned_rows)


def clean_json_log(file_path, output_path):
    """Clean JSON log files by validating structure and removing invalid entries."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both list and dict formats
        if isinstance(data, list):
            cleaned_data = [item for item in data if item and isinstance(item, dict)]
        elif isinstance(data, dict):
            cleaned_data = data
        else:
            cleaned_data = []
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(cleaned_data, f, indent=2, ensure_ascii=False)
        
        return len(cleaned_data) if isinstance(cleaned_data, list) else 1
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return 0


def clean_text_log(file_path, output_path):
    """Clean text log files by removing empty lines and normalizing format."""
    cleaned_lines = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            cleaned_line = line.strip()
            if cleaned_line and not cleaned_line.startswith('#'):
                cleaned_lines.append(cleaned_line)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(cleaned_lines))
    
    return len(cleaned_lines)


def clean_logs(raw_data_dir, cleaned_data_dir, month=None):
    """
    Main function to clean all logs in raw-data directory.
    
    Args:
        raw_data_dir: Path to raw data directory
        cleaned_data_dir: Path to cleaned data directory
        month: Optional month identifier (YYYY-MM format)
    """
    raw_path = Path(raw_data_dir)
    cleaned_path = Path(cleaned_data_dir)
    
    if month:
        cleaned_path = cleaned_path / month
        cleaned_path.mkdir(parents=True, exist_ok=True)
    else:
        cleaned_path.mkdir(parents=True, exist_ok=True)
    
    if not raw_path.exists():
        print(f"Raw data directory not found: {raw_path}")
        return
    
    stats = {'csv': 0, 'json': 0, 'txt': 0, 'other': 0}
    
    # Get all files (supporting both Path.iterdir() and glob patterns)
    files = list(raw_path.glob('*.csv')) + list(raw_path.glob('*.json')) + \
            list(raw_path.glob('*.txt')) + list(raw_path.glob('*.log'))
    
    # Also check direct directory listing for any other files
    for file_path in raw_path.iterdir():
        if file_path.is_file() and file_path not in files:
            files.append(file_path)
    
    for file_path in files:
        if not file_path.is_file():
            continue
            
        file_ext = file_path.suffix.lower()
        output_path = cleaned_path / f"cleaned_{file_path.name}"
        
        try:
            if file_ext == '.csv':
                count = clean_csv_log(file_path, output_path)
                stats['csv'] += count
                print(f"Cleaned CSV: {file_path.name} -> {count} rows")
            elif file_ext == '.json':
                count = clean_json_log(file_path, output_path)
                stats['json'] += count
                print(f"Cleaned JSON: {file_path.name} -> {count} entries")
            elif file_ext in ['.txt', '.log']:
                count = clean_text_log(file_path, output_path)
                stats['txt'] += count
                print(f"Cleaned text log: {file_path.name} -> {count} lines")
            else:
                stats['other'] += 1
                print(f"Skipped unsupported format: {file_path.name}")
        except Exception as e:
            print(f"Error cleaning {file_path.name}: {e}")
    
    print(f"\nCleaning complete. Stats: {stats}")
    return stats


if __name__ == "__main__":
    import sys
    
    # Default paths
    script_dir = Path(__file__).parent.parent
    raw_data = script_dir / "raw-data"
    cleaned_data = script_dir / "cleaned-data"
    
    # Get month from command line or use current month
    month = sys.argv[1] if len(sys.argv) > 1 else datetime.now().strftime("%Y-%m")
    
    clean_logs(raw_data, cleaned_data, month)

