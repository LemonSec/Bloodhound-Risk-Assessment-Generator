# BloodHound IR Analyzer

A PowerShell tool that parses SharpHound ZIP collections and generates incident response reports highlighting Active Directory security risks.

## What It Does

Reads BloodHound JSON data and produces an **HTML report** and **multi-tab XLSX workbook** covering 18 analysis areas:

| # | Section | # | Section |
|---|---------|---|---------|
| 1 | Enabled DA & EA | 10 | Password Never Expires |
| 2 | All DA/EA Members | 11 | Inactive Accounts (90d) |
| 3 | Recently Created Users (90d) | 12 | Not in Protected Users |
| 4 | Kerberoastable Users | 13 | LAPS Missing |
| 5 | AS-REP Roastable Users | 14 | Domain Controllers |
| 6 | Unconstrained Delegation | 15 | OS Breakdown |
| 7 | Constrained Delegation | 16 | Domain Trusts |
| 8 | High-Value Targets | 17 | Password Not Required (PASSWD_NOTREQD) |
| 9 | Stale Passwords (>365d) | 18 | Password Policy & Best Practices |

The HTML report uses a dark theme with expandable tables (first 10 rows shown, click to expand) and includes IR context with MITRE ATT&CK references for each section. The XLSX workbook contains a dedicated tab per section.

## Usage

```powershell
.\Analyze-BloodHoundData.ps1 -ZipPath .\sharphound_collection.zip
```

This generates two files in the current directory:
- `BloodHound_IR_Report.html`
- `BloodHound_IR_Report.xlsx`

Custom output paths:

```powershell
.\Analyze-BloodHoundData.ps1 -ZipPath .\sharphound.zip -OutputPath .\report.html -XlsxPath .\report.xlsx
```

## Requirements

- PowerShell 5.1+
- `BH_IR_Template.html` must be in the same directory as the script
- [ImportExcel](https://github.com/dfinke/ImportExcel) module for XLSX output (auto-installs if missing; falls back to CSV export)

## Files

```
├── Analyze-BloodHoundData.ps1    # Main script
├── BH_IR_Template.html           # HTML report template
├── README.md
└── example_data/
    ├── sample_bloodhound.zip     # Sample SharpHound collection
    ├── BloodHound_IR_Report.html # Sample HTML report output
    └── BloodHound_IR_Report.xlsx # Sample XLSX report output
```
