# Monthly Cybersecurity Report System

An automated system for processing monthly security data and generating comprehensive cybersecurity reports.

## Directory Structure

```
/monthly-report-system/
│
├── /raw-data/               # Put logs, CSV, JSON here each month
├── /cleaned-data/           # After running cleaning scripts
├── /scripts/                # Python scripts for automation
│     ├── clean_logs.py      # Cleans and filters data (pandas-based)
│     ├── aggregate.py       # Aggregates data (pandas-based)
│     ├── compare_months.py  # Compares months (pandas-based)
│     └── analyze_security.py # Security analysis
├── /templates/
│     ├── report-prompt.md
│     ├── report-structure.md
│     └── cybersecurity-report-template.md
├── /history/
│     └── (auto saves previous months)
├── generate_report.py       # Fully automated report generation
└── prepare_report.py        # Prepares data + AI prompt
```

## Two Workflow Options

### Option 1: Fully Automated (Recommended)

**Use `generate_report.py`** for completely automated report generation.

#### Quick Start

1. **Add Your Data**
   Place your raw security data files (CSV, JSON, or text logs) in the `raw-data/` directory.

2. **Run the Script**
   ```bash
   python generate_report.py [YYYY-MM]
   ```
   
   If you don't specify a month, it will use the current month.
   
   Example:
   ```bash
   python generate_report.py 2024-11
   ```

3. **Review Output**
   - **Cleaned data**: `cleaned-data/[MONTH]/`
   - **Aggregated CSV**: `cleaned-data/aggregated.csv`
   - **Aggregated statistics**: `cleaned-data/aggregated_[MONTH].json`
   - **Comparison summary**: `cleaned-data/comparison_summary.csv`
   - **Final report**: `history/report_[MONTH].md`
   - **Security analysis**: `history/security_analysis_[MONTH].json`

#### What It Does Automatically

1. ✅ **Cleans raw data** - Filters by severity (medium, high, critical), removes duplicates
2. ✅ **Aggregates data** - Combines all CSV files, generates statistics
3. ✅ **Analyzes security** - Extracts threats, incidents, vulnerabilities
4. ✅ **Compares months** - Month-over-month comparison (CSV + detailed JSON)
5. ✅ **Generates report** - Complete cybersecurity report with all sections

#### Report Sections Generated

1. Executive Summary
2. Incident Overview (table format)
3. Alert Trends
4. System Health & Vulnerabilities
5. Threat Intelligence Overview
6. Recommendations
7. Month-to-Month Comparison
8. Data Tables
9. Graph Descriptions

### Option 2: AI-Assisted Generation

**Use `prepare_report.py`** to prepare data and generate an AI prompt.

```bash
python prepare_report.py
```

This will:
- Run all data processing scripts
- Create `ai_request.txt` with detailed instructions
- Show you exactly what to tell the AI IDE

Then tell the AI IDE:
```
"Generate Monthly_Report_2024-11.md using ai_request.txt and all data in the project folder."
```

## Scripts Overview

### `generate_report.py` (Main - Fully Automated)
**One command does everything!**

- Orchestrates entire pipeline
- Cleans, aggregates, analyzes, compares, and generates report
- No manual steps required

**Usage:**
```bash
python generate_report.py [YYYY-MM]
```

### `prepare_report.py` (AI-Assisted Workflow)
- Runs data processing scripts
- Creates AI prompt file
- Prepares for AI IDE generation

**Usage:**
```bash
python prepare_report.py
```

### `scripts/clean_logs.py`
- Cleans and preprocesses raw data files (pandas-based)
- Filters by severity: medium, high, critical only
- Removes duplicates
- Supports CSV, JSON, and text log formats

**Usage:**
```bash
python scripts/clean_logs.py [YYYY-MM]
```

### `scripts/aggregate.py`
- Aggregates cleaned data using pandas
- Creates `aggregated.csv` (combined all CSV files)
- Generates detailed JSON statistics

**Usage:**
```bash
python scripts/aggregate.py [YYYY-MM]
```

### `scripts/compare_months.py`
- Compares data between months (pandas-based)
- Creates `comparison_summary.csv`
- Generates detailed comparison reports

**Usage:**
```bash
python scripts/compare_months.py [MONTH1] [MONTH2]
# Or run without args to auto-compare most recent files
```

### `scripts/analyze_security.py`
- Extracts threats, incidents, vulnerabilities
- Classifies by severity
- Identifies patterns and anomalies

## Workflow

1. **Data Collection**: Add raw data files to `raw-data/` directory
2. **Cleaning**: Run `clean_logs.py` (or let `generate_report.py` handle it)
3. **Aggregation**: Run `aggregate.py` (or let `generate_report.py` handle it)
4. **Comparison**: Automatically compares with previous month if available
5. **Report Generation**: Creates markdown report in `history/` directory

## Supported File Formats

- **CSV**: Comma-separated values with headers
- **JSON**: Array of objects or single object
- **Text Logs**: Plain text files (.txt, .log)

## Customization

### Report Templates
- Edit `templates/report-structure.md` to customize report format
- Use `templates/report-prompt.md` as a guide for AI-assisted report generation

### Scripts
- Modify scripts in `scripts/` directory to add custom processing logic
- Extend aggregation functions to calculate domain-specific metrics

## Requirements

- **Python 3.7+**
- **pandas** (recommended, for faster processing)
  ```bash
  pip install pandas
  ```
- Standard library works as fallback if pandas not available

## Notes

- All scripts automatically create necessary directories
- Previous month data is required for comparison features
- Reports are saved in markdown format for easy viewing and editing
- Aggregated data is saved in JSON format for programmatic access

