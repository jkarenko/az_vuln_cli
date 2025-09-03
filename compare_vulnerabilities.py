#!/usr/bin/env python3
"""
Compare vulnerabilities between production and latest images
to identify which updates would reduce security risk.
"""

import pandas as pd
import sys
import os
from pathlib import Path

def load_vulnerability_data(csv_path):
    """Load vulnerability data from CSV file."""
    try:
        df = pd.read_csv(csv_path)
        return df
    except FileNotFoundError:
        print(f"Warning: {csv_path} not found")
        return pd.DataFrame()

def compare_vulnerabilities():
    """Compare production vs latest vulnerabilities."""
    
    # Load data
    prod_path = "reports/production/vulnerabilities_summary.csv"
    latest_path = "reports/latest/vulnerabilities_summary.csv"
    
    print("=== Production vs Latest Vulnerability Comparison ===\n")
    
    if not os.path.exists(prod_path):
        print(f"❌ Production data not found: {prod_path}")
        print("Run ./scan_production_vs_latest.sh first!")
        return
        
    if not os.path.exists(latest_path):
        print(f"❌ Latest data not found: {latest_path}")
        print("Run ./scan_production_vs_latest.sh first!")
        return
    
    prod_df = load_vulnerability_data(prod_path)
    latest_df = load_vulnerability_data(latest_path)
    
    if prod_df.empty or latest_df.empty:
        print("❌ No vulnerability data to compare")
        return
    
    print(f"📊 Data Summary:")
    print(f"   Production packages: {len(prod_df)}")
    print(f"   Latest packages: {len(latest_df)}")
    print()
    
    # Group by severity for production
    prod_severity = prod_df.groupby('Priority').size() if 'Priority' in prod_df.columns else pd.Series()
    latest_severity = latest_df.groupby('Priority').size() if 'Priority' in latest_df.columns else pd.Series()
    
    print("🔥 Severity Comparison:")
    # Check what priority values actually exist and adapt
    all_priorities = set()
    if 'Priority' in prod_df.columns:
        all_priorities.update(prod_df['Priority'].unique())
    if 'Priority' in latest_df.columns:
        all_priorities.update(latest_df['Priority'].unique())
    
    # Use the actual priority values found, or fall back to expected ones
    if any(p in all_priorities for p in ['High', 'Medium', 'Low']):
        severities = ['High', 'Medium', 'Low']
    else:
        severities = ['High Priority', 'Medium Priority', 'Low Priority']
    
    for severity in severities:
        prod_count = prod_severity.get(severity, 0)
        latest_count = latest_severity.get(severity, 0)
        change = latest_count - prod_count
        
        if change < 0:
            indicator = f"✅ {abs(change)} fewer"
        elif change > 0:
            indicator = f"⚠️  {change} more"
        else:
            indicator = "➡️  no change"
            
        print(f"   {severity:15} | Prod: {prod_count:3} | Latest: {latest_count:3} | {indicator}")
    
    print()
    
    # Find packages that are in production but improved in latest
    # Handle both Package and Package_Name column names
    prod_pkg_col = 'Package_Name' if 'Package_Name' in prod_df.columns else 'Package'
    latest_pkg_col = 'Package_Name' if 'Package_Name' in latest_df.columns else 'Package'
    
    if prod_pkg_col in prod_df.columns and latest_pkg_col in latest_df.columns:
        prod_packages = set(prod_df[prod_pkg_col].tolist())
        latest_packages = set(latest_df[latest_pkg_col].tolist())
        
        # Packages fixed in latest (present in prod vulnerabilities, absent in latest)
        fixed_packages = prod_packages - latest_packages
        
        # New vulnerabilities in latest (absent in prod, present in latest)  
        new_vulns = latest_packages - prod_packages
        
        print("📈 Update Impact Analysis:")
        print(f"   🎯 Packages potentially FIXED in :latest: {len(fixed_packages)}")
        print(f"   ⚠️  New vulnerabilities in :latest: {len(new_vulns)}")
        
        if fixed_packages:
            print(f"\n✅ Top packages potentially fixed by updating to :latest from ACR:")
            for i, pkg in enumerate(sorted(fixed_packages)[:10]):
                print(f"   {i+1:2}. {pkg}")
                
        if new_vulns:
            print(f"\n⚠️  New vulnerabilities introduced in :latest from ACR:")
            for i, pkg in enumerate(sorted(new_vulns)[:10]):
                print(f"   {i+1:2}. {pkg}")
    
    print()
    print("📋 Recommendation:")
    
    total_prod = len(prod_df)
    total_latest = len(latest_df)
    
    if total_latest < total_prod:
        reduction = total_prod - total_latest
        percentage = (reduction / total_prod) * 100
        print(f"   ✅ DEPLOY :latest images from ACR - reduces vulnerabilities by {reduction} ({percentage:.1f}%)")
    elif total_latest > total_prod:
        increase = total_latest - total_prod
        percentage = (increase / total_prod) * 100
        print(f"   ⚠️  CAUTION - :latest images from ACR have {increase} MORE vulnerabilities ({percentage:.1f}%)")
    else:
        print(f"   ➡️  NEUTRAL - :latest images from ACR have same vulnerability count")
    
    print()
    print("📊 Next Steps:")
    print("1. Import CSV files to Google Sheets or Excel for detailed package-level analysis")
    print("2. Focus on Critical/High severity differences") 
    print("3. Test :latest images from ACR in dev environment")
    print("4. Deploy updates that reduce overall risk")
    
    # Save comparison results to file
    comparison_dir = Path("reports/comparison")
    comparison_dir.mkdir(parents=True, exist_ok=True)
    comparison_file = comparison_dir / "vulnerability_comparison_summary.txt"
    with open(comparison_file, 'w') as f:
        f.write("=== Production vs Latest Vulnerability Comparison ===\n\n")
        f.write(f"📊 Data Summary:\n")
        f.write(f"   Production packages: {len(prod_df)}\n")
        f.write(f"   Latest packages: {len(latest_df)}\n\n")
        
        f.write("🔥 Severity Comparison:\n")
        for severity in severities:
            prod_count = prod_severity.get(severity, 0)
            latest_count = latest_severity.get(severity, 0)
            change = latest_count - prod_count
            
            if change < 0:
                indicator = f"✅ {abs(change)} fewer"
            elif change > 0:
                indicator = f"⚠️  {change} more"
            else:
                indicator = "➡️  no change"
                
            f.write(f"   {severity:15} | Prod: {prod_count:3} | Latest: {latest_count:3} | {indicator}\n")
        
        # Package analysis  
        if prod_pkg_col in prod_df.columns and latest_pkg_col in latest_df.columns:
            prod_packages = set(prod_df[prod_pkg_col].tolist())
            latest_packages = set(latest_df[latest_pkg_col].tolist())
            fixed_packages = prod_packages - latest_packages
            new_vulns = latest_packages - prod_packages
            
            f.write(f"\n📈 Update Impact Analysis:\n")
            f.write(f"   🎯 Packages potentially FIXED in :latest from ACR: {len(fixed_packages)}\n")
            f.write(f"   ⚠️  New vulnerabilities in :latest from ACR: {len(new_vulns)}\n")
        
        f.write(f"\n📋 Recommendation:\n")
        total_prod = len(prod_df)
        total_latest = len(latest_df)
        
        if total_latest < total_prod:
            reduction = total_prod - total_latest
            percentage = (reduction / total_prod) * 100
            f.write(f"   ✅ DEPLOY :latest images from ACR - reduces vulnerabilities by {reduction} ({percentage:.1f}%)\n")
        elif total_latest > total_prod:
            increase = total_latest - total_prod
            percentage = (increase / total_prod) * 100
            f.write(f"   ⚠️  CAUTION - :latest images from ACR have {increase} MORE vulnerabilities ({percentage:.1f}%)\n")
        else:
            f.write(f"   ➡️  NEUTRAL - :latest images from ACR have same vulnerability count\n")
    
    print(f"\n💾 Comparison results saved to: {comparison_file}")

if __name__ == "__main__":
    compare_vulnerabilities()
