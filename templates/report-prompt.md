# Monthly Report Generation Prompt

Use this template when generating monthly reports with AI assistance.

## Context
Generate a comprehensive monthly report for **[MONTH YEAR]** based on the cleaned and aggregated data.

## Data Sources
- Cleaned data location: `cleaned-data/[MONTH]/`
- Aggregated statistics: `cleaned-data/aggregated_[MONTH].json`
- Previous month comparison (if available): `history/comparison_*.md`

## Report Structure
Follow the structure defined in `report-structure.md`.

## Key Metrics to Include
1. **Volume Metrics**
   - Total number of records/entries processed
   - Number of data sources
   - Data quality metrics (completeness, validity)

2. **Trend Analysis**
   - Month-over-month changes
   - Key patterns and anomalies
   - Notable events or incidents

3. **Insights**
   - Key findings from the data
   - Recommendations for next month
   - Action items

4. **Data Quality**
   - Cleaning statistics
   - Issues encountered
   - Data validation results

## Instructions
1. Review all cleaned data files for the month
2. Analyze aggregated statistics
3. Compare with previous month (if available)
4. Generate insights and recommendations
5. Format according to report structure template
6. Save to `history/` directory with filename: `report_[MONTH].md`

## Output Format
- Markdown format
- Include charts/graphs descriptions where applicable
- Use clear headings and sections
- Include data tables for key metrics
- Add executive summary at the beginning




