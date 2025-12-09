"""
Master script to prepare data and generate AI prompt for report generation.
Runs all cleaning, aggregation, and comparison scripts, then creates a prompt
for the AI IDE to generate the final report.
"""

import subprocess
import os
from datetime import datetime
from pathlib import Path


def main():
    # Get current month
    MONTH = datetime.now().strftime("%B %Y")
    MONTH_SHORT = datetime.now().strftime("%Y-%m")
    OUTPUT = f"Monthly_Report_{MONTH_SHORT}.md"
    
    # Get script directory
    script_dir = Path(__file__).parent
    
    print("\n" + "=" * 60)
    print("Monthly Cybersecurity Report Preparation")
    print("=" * 60)
    print(f"\nReport Period: {MONTH}")
    print(f"Output File: {OUTPUT}\n")
    
    # Step 1: Run cleaning scripts
    print("\n==== Step 1: Running cleaning scripts ====\n")
    try:
        clean_result = subprocess.run(
            ["python", str(script_dir / "scripts" / "clean_logs.py"), MONTH_SHORT],
            cwd=script_dir,
            check=False
        )
        if clean_result.returncode != 0:
            print("⚠ Warning: Cleaning script had issues")
    except Exception as e:
        print(f"✗ Error running clean_logs.py: {e}")
    
    # Step 2: Run aggregation
    print("\n==== Step 2: Running aggregation ====\n")
    try:
        agg_result = subprocess.run(
            ["python", str(script_dir / "scripts" / "aggregate.py"), MONTH_SHORT],
            cwd=script_dir,
            check=False
        )
        if agg_result.returncode != 0:
            print("⚠ Warning: Aggregation script had issues")
    except Exception as e:
        print(f"✗ Error running aggregate.py: {e}")
    
    # Step 3: Run comparison
    print("\n==== Step 3: Running comparison ====\n")
    try:
        comp_result = subprocess.run(
            ["python", str(script_dir / "scripts" / "compare_months.py")],
            cwd=script_dir,
            check=False
        )
        if comp_result.returncode != 0:
            print("⚠ Warning: Comparison script had issues")
    except Exception as e:
        print(f"✗ Error running compare_months.py: {e}")
    
    # Step 4: Create AI prompt
    print("\n==== Step 4: Creating AI prompt ====\n")
    
    # Read the report prompt template if it exists
    prompt_template_path = script_dir / "templates" / "report-prompt.md"
    base_prompt = ""
    if prompt_template_path.exists():
        with open(prompt_template_path, 'r', encoding='utf-8') as f:
            base_prompt = f.read()
    
    # Build comprehensive prompt
    prompt = f"""# Monthly Cybersecurity Report Generation Request

## Report Period
{MONTH} ({MONTH_SHORT})

## Instructions

You are an expert cybersecurity analyst creating a Monthly Cybersecurity Report.

### Your Job:
- Read ALL files in /raw-data and /cleaned-data
- Read last month's report in /history (if present)
- Use the structure in templates/report-structure.md
- Extract meaningful insights, threats, anomalies, and patterns
- Summarize risks in simple language

### Data Sources Available:
- Cleaned data: `cleaned-data/{MONTH_SHORT}/` (or `cleaned-data/` root)
- Aggregated CSV: `cleaned-data/aggregated.csv`
- Comparison summary: `cleaned-data/comparison_summary.csv`
- Previous month report: `history/report_*.md` (if available)
- Security analysis: `cleaned-data/security_analysis_{MONTH_SHORT}.json` (if available)

### Report Structure:
Follow the structure defined in `templates/report-structure.md`:

1. Executive Summary
2. Incident Overview (table format)
3. Alert Trends
4. System Health & Vulnerabilities
5. Threat Intelligence Overview
6. Recommendations
7. Month-to-Month Comparison
8. Data Tables
9. Graph Descriptions

### Output Requirements:
- Clear, professional, non-technical where necessary
- Include bullet points, tables, and concise summaries
- Use the exact template format from templates/report-structure.md
- Save output to: `{OUTPUT}`

### Key Metrics to Include:
1. **Volume Metrics**
   - Total number of records/entries processed
   - Number of data sources
   - Data quality metrics (completeness, validity)

2. **Security Metrics**
   - Total incidents, threats, vulnerabilities
   - Severity breakdown (Critical, High, Medium, Low)
   - Top threat sources (IP addresses)
   - Top active users

3. **Trend Analysis**
   - Month-over-month changes (use comparison_summary.csv)
   - Key patterns and anomalies
   - Notable events or incidents

4. **Insights**
   - Key findings from the data
   - Recommendations for next month
   - Action items

### Template Reference:
{base_prompt}

---

## Final Instructions

Generate a comprehensive monthly cybersecurity report for {MONTH} based on all available cleaned and aggregated data.

Use the structure from templates/report-structure.md and save the output to: `{OUTPUT}`

Make sure to:
- Read all cleaned data files
- Analyze aggregated statistics
- Compare with previous month (if available)
- Generate insights and recommendations
- Format according to report structure template
"""
    
    # Save prompt to file
    prompt_path = script_dir / "ai_request.txt"
    with open(prompt_path, 'w', encoding='utf-8') as f:
        f.write(prompt)
    
    print(f"✓ AI prompt saved to: {prompt_path}")
    
    # Print instructions
    print("\n" + "=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("\nTell the AI IDE:")
    print(f'👉 "Generate {OUTPUT} using ai_request.txt and all data in the project folder."')
    print("\nOr copy this command:")
    print(f'   "Generate {OUTPUT} using ai_request.txt and all data in the project folder."')
    print("\n" + "=" * 60)
    print("\nData preparation complete! ✓")
    print(f"All scripts have been run. Ready for AI report generation.")
    print(f"\nExpected output file: {OUTPUT}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()




