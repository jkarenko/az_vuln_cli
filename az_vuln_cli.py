#!/usr/bin/env python3
"""
az_vuln_cli
A unified interface for container vulnerability scanning and analysis.

Supports production, development, and latest image vulnerability analysis
across multiple Azure Container Registries and subscriptions.
"""

import sys
import subprocess
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

def get_script_name() -> str:
    """Get the name of the current script for dynamic command suggestions"""
    script_name = os.path.basename(sys.argv[0])
    # Handle cases where script is run as python module
    if script_name.endswith('.py'):
        return f"python3 {script_name}"
    else:
        return script_name

def load_config() -> Dict:
    """Load environment configuration from environments.yaml"""
    config_path = Path('environments.yaml')
    if not config_path.exists():
        console.print("❌ environments.yaml not found")
        sys.exit(1)
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        console.print(f"❌ Error loading environments.yaml: {e}")
        sys.exit(1)

class SystemStatus:
    """Check system status and authentication"""
    
    def __init__(self, quick=False):
        self.status = {}
        if quick:
            self._check_quick_status()
        else:
            self._check_all_status()
    
    def _check_quick_status(self):
        """Quick status check - no network calls"""
        self.status = {
            'azure_cli': {'status': 'checking', 'message': 'Checking...'},
            'acr_auth': {},
            'inventory': self._check_inventory_files(),
            'recent_scans': self._check_recent_scans(),
            'reports': self._check_available_reports()
        }
    
    def _check_all_status(self):
        """Check all system components (including slow network calls)"""
        self.status = {
            'azure_cli': self._check_azure_cli(),
            'acr_auth': self._check_acr_auth(),
            'inventory': self._check_inventory_files(),
            'recent_scans': self._check_recent_scans(),
            'reports': self._check_available_reports()
        }
    
    def _check_azure_cli(self) -> Dict:
        """Check Azure CLI authentication status"""
        try:
            result = subprocess.run(['az', 'account', 'show'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                account_info = json.loads(result.stdout)
                return {
                    'status': 'authenticated',
                    'user': account_info.get('user', {}).get('name', 'Unknown'),
                    'subscription': account_info.get('name', 'Unknown')
                }
            else:
                return {'status': 'not_authenticated', 'message': f'Run: {get_script_name()} auth'}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return {'status': 'error', 'message': 'Azure CLI not installed or accessible'}
    
    def _check_acr_auth(self) -> Dict:
        """Check ACR authentication status (fast check)"""
        try:
            config = load_config()
        except:
            return {'error': {'status': 'error', 'message': 'Could not load configuration'}}
        
        registries = {}
        for env_name, env_config in config['environments'].items():
            for reg_name, acr_config in env_config['acrs'].items():
                registries[reg_name] = acr_config['subscription']
        acr_status = {}
        
        # Store current subscription
        try:
            current_sub = subprocess.run(['az', 'account', 'show', '--query', 'name', '--output', 'tsv'], 
                                       capture_output=True, text=True, timeout=5).stdout.strip()
        except:
            current_sub = None
        
        for registry, subscription in registries.items():
            try:
                # Switch to correct subscription and check registry
                subprocess.run(['az', 'account', 'set', '--subscription', subscription], 
                             capture_output=True, text=True, timeout=5)
                result = subprocess.run(['az', 'acr', 'show', '--name', registry], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Try to count repositories if we can access the registry
                    try:
                        repo_result = subprocess.run(['az', 'acr', 'repository', 'list', '--name', registry, '--output', 'tsv'], 
                                                   capture_output=True, text=True, timeout=10)
                        if repo_result.returncode == 0:
                            repo_count = len([line for line in repo_result.stdout.strip().split('\n') if line.strip()])
                            acr_status[registry] = {'status': 'authenticated', 'repositories': str(repo_count), 'subscription': subscription}
                        else:
                            acr_status[registry] = {'status': 'authenticated', 'repositories': 'accessible', 'subscription': subscription}
                    except:
                        acr_status[registry] = {'status': 'authenticated', 'repositories': 'accessible', 'subscription': subscription}
                else:
                    acr_status[registry] = {'status': 'not_authenticated', 'subscription': subscription}
            except (subprocess.TimeoutExpired, json.JSONDecodeError):
                acr_status[registry] = {'status': 'error', 'subscription': subscription}
        
        # Restore original subscription
        if current_sub:
            try:
                subprocess.run(['az', 'account', 'set', '--subscription', current_sub], 
                             capture_output=True, text=True, timeout=5)
            except:
                pass
        
        return acr_status
    
    def _check_inventory_files(self) -> Dict:
        """Check status of image inventory files"""
        try:
            config = load_config()
        except:
            return {'error': {'status': 'error', 'message': 'Could not load configuration'}}
        
        inventory_files = []
        
        # Add environment-specific files
        for env_name, env_config in config['environments'].items():
            inventory_files.append(env_config['aks']['inventory_file'])
            for reg_name, acr_config in env_config['acrs'].items():
                inventory_files.append(acr_config['inventory_file'])
        
        # Add master inventory
        inventory_files.append(config['master_inventory']['output_file'])
        
        # Remove duplicates while preserving order
        seen = set()
        inventory_files = [x for x in inventory_files if not (x in seen or seen.add(x))]
        
        inventory_status = {}
        for filename in inventory_files:
            filepath = Path(filename)
            if filepath.exists():
                stat = filepath.stat()
                modified = datetime.fromtimestamp(stat.st_mtime)
                age_hours = (datetime.now() - modified).total_seconds() / 3600
                
                # Count lines/images
                try:
                    with open(filepath, 'r') as f:
                        line_count = sum(1 for line in f if line.strip())
                    
                    inventory_status[filename] = {
                        'status': 'present',
                        'count': line_count,
                        'age_hours': age_hours,
                        'modified': modified
                    }
                except:
                    inventory_status[filename] = {'status': 'error', 'message': 'Cannot read file'}
            else:
                inventory_status[filename] = {'status': 'missing'}
        
        return inventory_status
    
    def _check_recent_scans(self) -> Dict:
        """Check for recent scan results using configuration"""
        try:
            config = load_config()
            scan_indicators = [('os_versions', 'reports/os-versions/')]
            
            # Add environment-specific scan directories from config
            for env_name, output_dir in config['scan_output']['environments'].items():
                if env_name != 'custom':  # Skip custom scans from status
                    scan_indicators.extend([
                        (f'{env_name}_sboms', f'sbom_reports/{output_dir}/'),
                        (f'{env_name}_reports', f'reports/{output_dir}/')
                    ])
        except:
            # Fallback to hardcoded directories if config fails
            scan_indicators = [
                ('os_versions', 'reports/os-versions/'),
                ('production_sboms', 'sbom_reports/production/'),
                ('latest_sboms', 'sbom_reports/latest/'),
                ('production_reports', 'reports/production/'),
                ('latest_reports', 'reports/latest/')
            ]
        
        scan_status = {}
        for scan_type, directory in scan_indicators:
            dir_path = Path(directory)
            if dir_path.exists():
                # Find most recent file
                files = list(dir_path.glob('*.csv')) + list(dir_path.glob('*.json'))
                if files:
                    most_recent = max(files, key=lambda f: f.stat().st_mtime)
                    modified = datetime.fromtimestamp(most_recent.stat().st_mtime)
                    age_hours = (datetime.now() - modified).total_seconds() / 3600
                    
                    scan_status[scan_type] = {
                        'status': 'present',
                        'last_scan': modified,
                        'age_hours': age_hours,
                        'file_count': len(files)
                    }
                else:
                    scan_status[scan_type] = {'status': 'empty_directory'}
            else:
                scan_status[scan_type] = {'status': 'no_directory'}
        
        return scan_status
    
    def _check_available_reports(self) -> Dict:
        """Check what reports are available using configuration"""
        try:
            config = load_config()
            report_files = [
                'reports/analysis/remediation_tracking.csv',
                'reports/analysis/remediation_summary.csv', 
                'reports/analysis/jira_epic.md'
            ]
            
            # Add environment-specific summary reports from config
            for env_name, output_dir in config['scan_output']['environments'].items():
                if env_name != 'custom':  # Skip custom scans
                    report_files.append(f'reports/{output_dir}/vulnerabilities_summary.csv')
                    # Also check for --include-latest reports
                    report_files.append(f'reports/{output_dir}/latest_vulnerabilities_summary.csv')
        except:
            # Fallback to original paths if config fails
            report_files = [
                'remediation_tracking.csv',
                'remediation_summary.csv', 
                'jira_epic.md',
                'reports/production/vulnerabilities_summary.csv',
                'reports/latest/vulnerabilities_summary.csv'
            ]
        
        report_status = {}
        for filename in report_files:
            filepath = Path(filename)
            if filepath.exists():
                stat = filepath.stat()
                modified = datetime.fromtimestamp(stat.st_mtime)
                age_hours = (datetime.now() - modified).total_seconds() / 3600
                size_mb = stat.st_size / (1024 * 1024)
                
                report_status[filename] = {
                    'status': 'present',
                    'age_hours': age_hours,
                    'size_mb': size_mb,
                    'modified': modified
                }
            else:
                report_status[filename] = {'status': 'missing'}
        
        return report_status

def format_age(age_hours: float) -> str:
    """Format age in hours to human readable format"""
    if age_hours < 1:
        return f"{int(age_hours * 60)}m ago"
    elif age_hours < 24:
        return f"{int(age_hours)}h ago"
    else:
        return f"{int(age_hours / 24)}d ago"

def get_status_icon(status: str, age_hours: Optional[float] = None) -> str:
    """Get appropriate status icon"""
    if status == 'authenticated' or status == 'present':
        if age_hours is not None:
            if age_hours > 72:  # 3 days
                return "⚠️ "
            elif age_hours > 24:  # 1 day  
                return "🟡"
            else:
                return "✅"
        return "✅"
    elif status == 'not_authenticated' or status == 'missing':
        return "❌"
    elif status == 'error':
        return "🚨"
    else:
        return "❓"

def _run_os_analysis(input_file: str, output_csv: str):
    """Run OS version analysis using optimized method"""
    try:
        # Use the optimized get_os_versions.py (no vulnerability scanning)
        result = subprocess.run([
            'python3', 'get_os_versions.py', '--csv', output_csv, '--file', input_file
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print(f"  ✅ OS versions analyzed: {output_csv}")
        else:
            console.print(f"  ⚠️  OS version analysis failed")
    except Exception as e:
        console.print(f"  ⚠️  OS version analysis error: {e}")

def _run_os_analysis_from_sboms(sbom_dir: str, output_csv: str):
    """Extract OS information from existing SBOM files (fastest method)"""
    try:
        result = subprocess.run([
            'python3', 'extract_os_from_sboms.py', 
            '--directory', sbom_dir, '--csv', output_csv
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print(f"  ✅ OS versions extracted from SBOMs: {output_csv}")
            return True
        else:
            console.print(f"  ⚠️  SBOM-based OS extraction failed")
            return False
    except Exception as e:
        console.print(f"  ⚠️  SBOM-based OS extraction error: {e}")
        return False

# CLI Commands
@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """az_vuln_cli
    
    A unified interface for container vulnerability scanning and analysis.
    Use subcommands for direct CLI operations.
    """
    if ctx.invoked_subcommand is None:
        console.print("📋 Available commands:")
        console.print(ctx.get_help())

@cli.command()
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
@click.option('--quick', is_flag=True, help='Quick status check (no network calls)')
def status(output_json, quick):
    """Show system status and health checks for all environments (prod/dev)"""
    system_status = SystemStatus(quick=quick)
    
    if output_json:
        click.echo(json.dumps(system_status.status, indent=2, default=str))
        return
    
    console.print("\n[bold blue]Azure Vulnerability Analysis - System Status[/bold blue]\n")
    
    # Authentication Status
    auth_table = Table(title="🔐 Authentication Status", expand=False)
    auth_table.add_column("Service", style="cyan")
    auth_table.add_column("Subscription", style="yellow")
    auth_table.add_column("Status", style="green")
    auth_table.add_column("Details", style="dim")
    for column in auth_table.columns:
        if column.header != "Status":
            column.no_wrap = True
    
    azure_status = system_status.status['azure_cli']
    auth_table.add_row(
        "Azure CLI",
        azure_status.get('subscription', 'N/A'),
        f"{get_status_icon(azure_status['status'])} {azure_status['status'].title()}",
        azure_status.get('user', azure_status.get('message', ''))
    )
    
    for registry, acr_status in system_status.status['acr_auth'].items():
        status_text = acr_status['status'].title()
        if acr_status['status'] == 'authenticated':
            repo_info = acr_status.get('repositories', 'N/A')
            if repo_info != 'N/A':
                status_text += f"\n({repo_info} repos)"
            else:
                status_text += "\n(connected)"
        auth_table.add_row(
            f"ACR {registry}",
            acr_status.get('subscription', 'N/A'),
            f"{get_status_icon(acr_status['status'])} {status_text}",
            ""
        )
    
    console.print(auth_table)
    console.print()
    
    # Inventory Status
    inventory_table = Table(title="📋 Inventory Status", expand=False) 
    inventory_table.add_column("File", style="cyan")
    inventory_table.add_column("Status", style="green")
    inventory_table.add_column("Count", justify="right")
    inventory_table.add_column("Last Updated", style="dim")
    for column in inventory_table.columns:
        column.no_wrap = True
    
    for filename, inv_status in system_status.status['inventory'].items():
        if inv_status['status'] == 'present':
            inventory_table.add_row(
                filename,
                f"{get_status_icon(inv_status['status'], inv_status['age_hours'])} Present",
                str(inv_status['count']),
                format_age(inv_status['age_hours'])
            )
        else:
            inventory_table.add_row(
                filename,
                f"{get_status_icon(inv_status['status'])} {inv_status['status'].title()}",
                "-",
                "-"
            )
    
    console.print(inventory_table)
    console.print()
    
    # Recent Scans
    scan_table = Table(title="📊 Recent Scan Results", expand=False)
    scan_table.add_column("Scan Type", style="cyan") 
    scan_table.add_column("Status", style="green")
    scan_table.add_column("Files", justify="right")
    scan_table.add_column("Last Run", style="dim")
    for column in scan_table.columns:
        column.no_wrap = True
    
    for scan_type, scan_status in system_status.status['recent_scans'].items():
        if scan_status['status'] == 'present':
            scan_table.add_row(
                scan_type.replace('_', ' ').title(),
                f"{get_status_icon(scan_status['status'], scan_status['age_hours'])} Complete",
                str(scan_status['file_count']),
                format_age(scan_status['age_hours'])
            )
        else:
            scan_table.add_row(
                scan_type.replace('_', ' ').title(), 
                f"{get_status_icon(scan_status['status'])} {scan_status['status'].replace('_', ' ').title()}",
                "-",
                "-"
            )
    
    console.print(scan_table)
    console.print()
    
    # Available Reports
    reports_table = Table(title="📄 Available Reports", expand=False)
    reports_table.add_column("Report", style="cyan")
    reports_table.add_column("Status", style="green") 
    reports_table.add_column("Size", justify="right")
    reports_table.add_column("Last Updated", style="dim")
    for column in reports_table.columns:
        column.no_wrap = True
    
    for filename, report_status in system_status.status['reports'].items():
        if report_status['status'] == 'present':
            size_mb = report_status.get('size_mb', 0)
            size_str = f"{size_mb:.1f} MB" if size_mb >= 1 else f"{size_mb*1000:.0f} KB"
            reports_table.add_row(
                filename.replace('reports/', ''),  # Remove 'reports/' prefix for cleaner display
                f"{get_status_icon(report_status['status'], report_status['age_hours'])} Present",
                size_str,
                format_age(report_status['age_hours'])
            )
        else:
            reports_table.add_row(
                filename.replace('reports/', ''),
                f"{get_status_icon(report_status['status'])} {report_status['status'].title()}",
                "-",
                "-"
            )
    
    console.print(reports_table)

@cli.command()
def auth():
    """Interactive Azure authentication setup"""
    console.print("[bold blue]🔐 Azure Authentication Setup[/bold blue]\n")
    
    # Check current status
    system_status = SystemStatus()
    azure_status = system_status.status['azure_cli']
    
    if azure_status['status'] == 'authenticated':
        console.print(f"✅ Already authenticated as: {azure_status.get('user', 'Unknown')}")
        if not click.confirm("Re-authenticate?"):
            return
    
    console.print("🔄 Starting Azure CLI login...")
    try:
        subprocess.run(['az', 'login'], check=True)
        console.print("✅ Azure CLI authentication successful")
        
        # Test ACR access using configuration
        console.print("🔄 Testing ACR access...")
        config = load_config()
        registries = set()
        
        # Collect all unique ACR registries from environments.yaml
        for env_name, env_config in config['environments'].items():
            for reg_name, acr_config in env_config['acrs'].items():
                registries.add((reg_name, acr_config['subscription']))
        
        for registry, subscription in registries:
            try:
                # Switch to correct subscription first
                subprocess.run(['az', 'account', 'set', '--subscription', subscription], 
                             check=True, capture_output=True)
                subprocess.run(['az', 'acr', 'login', '--name', registry], 
                             check=True, capture_output=True)
                console.print(f"✅ {registry} authentication successful")
            except subprocess.CalledProcessError:
                console.print(f"❌ {registry} authentication failed")
        
        # Setup AKS cluster credentials using configuration
        console.print("🔄 Setting up AKS cluster credentials...")
        
        for env_name, env_config in config['environments'].items():
            if 'aks' in env_config:
                aks_config = env_config['aks']
                try:
                    # Switch to correct subscription
                    subprocess.run(['az', 'account', 'set', '--subscription', aks_config['subscription']], 
                                 check=True, capture_output=True)
                    # Get AKS credentials
                    subprocess.run(['az', 'aks', 'get-credentials', 
                                  '--resource-group', aks_config['resource_group'],
                                  '--name', aks_config['cluster_name'], 
                                  '--overwrite-existing'], 
                                 check=True, capture_output=True)
                    console.print(f"✅ {aks_config['cluster_name']} credentials configured")
                except subprocess.CalledProcessError:
                    console.print(f"❌ {aks_config['cluster_name']} credential setup failed")
        
    except subprocess.CalledProcessError:
        console.print("❌ Azure authentication failed")

@cli.group()
def scan():
    """Security scanning operations - SBOM generation and vulnerability analysis"""
    pass

@scan.command('os-versions')
@click.option('--output', '-o', help='Output file path')
@click.option('--input-file', '-f', help='Input inventory file')
@click.option('--from-sboms', help='Extract from existing SBOM directory instead of scanning images')
@click.option('--fast', is_flag=True, help='Use fastest available method (SBOM-based if available)')
def scan_os_versions(output, input_file, from_sboms, fast):
    """Quick OS version and EOSL analysis for any environment"""
    if not output:
        output = f'reports/os-versions/scan_{datetime.now().strftime("%Y%m%d_%H%M")}.csv'
    
    # Create output directory if needed
    output_dir = os.path.dirname(output)
    if output_dir:  # Only create directory if there is one
        os.makedirs(output_dir, exist_ok=True)
    
    if from_sboms:
        # Extract from existing SBOM directory
        console.print(f"🚀 Extracting OS versions from SBOM directory...")
        console.print(f"📋 SBOM Directory: {from_sboms}")
        console.print(f"📊 Output: {output}")
        
        if not Path(from_sboms).exists():
            console.print(f"❌ SBOM directory not found: {from_sboms}")
            return
        
        if _run_os_analysis_from_sboms(from_sboms, output):
            console.print("✅ Ultra-fast OS version extraction complete")
        else:
            console.print("❌ SBOM-based OS extraction failed")
    
    elif fast:
        # Smart mode: use SBOMs if available, fallback to optimized scanning
        if not input_file:
            input_file = 'aks_running_images.txt'
        
        console.print(f"🏃 Smart OS version analysis (fastest available method)...")
        console.print(f"📋 Input: {input_file}")
        console.print(f"📊 Output: {output}")
        
        # Check if we have recent SBOM files for the images
        sbom_dirs = ['sbom_reports/production', 'sbom_reports/dev', 'sbom_reports/latest']
        best_sbom_dir = None
        sbom_file_count = 0
        
        for sbom_dir in sbom_dirs:
            if Path(sbom_dir).exists():
                files = list(Path(sbom_dir).glob('*.json'))
                if len(files) > sbom_file_count:
                    best_sbom_dir = sbom_dir
                    sbom_file_count = len(files)
        
        if best_sbom_dir and sbom_file_count > 0:
            console.print(f"🚀 Found {sbom_file_count} SBOM files in {best_sbom_dir}, using ultra-fast extraction")
            if _run_os_analysis_from_sboms(best_sbom_dir, output):
                console.print("✅ Ultra-fast OS version extraction complete")
            else:
                console.print("❌ SBOM extraction failed, falling back to optimized scanning")
                _run_os_analysis(input_file, output)
        else:
            console.print("🏃 No recent SBOMs found, using optimized Trivy scanning")
            _run_os_analysis(input_file, output)
    
    else:
        # Traditional mode with optimized scanning
        if not input_file:
            input_file = 'aks_running_images.txt'
        
        console.print(f"🔍 Starting optimized OS version analysis...")
        console.print(f"📋 Input: {input_file}")
        console.print(f"📊 Output: {output}")
        
        try:
            _run_os_analysis(input_file, output)
            console.print("✅ OS version analysis complete")
        except Exception as e:
            console.print(f"❌ OS version analysis failed: {e}")

@scan.command('production')
def scan_production():
    """Full production vulnerability analysis using configuration"""
    # Use scan all with prod environment (no redundant confirmation)
    ctx = click.get_current_context()
    try:
        ctx.invoke(scan_all, env='prod')
        console.print(f"💡 Run: {get_script_name()} reports generate --env prod")
    except Exception as e:
        console.print(f"❌ Production analysis failed: {e}")

@scan.command('dev')
def scan_dev():
    """Full development environment vulnerability analysis using configuration"""
    # Use scan all with dev environment (no redundant confirmation)
    ctx = click.get_current_context()
    try:
        ctx.invoke(scan_all, env='dev')
        console.print(f"💡 Run: {get_script_name()} reports generate --env dev")
    except Exception as e:
        console.print(f"❌ Development analysis failed: {e}")

@scan.command('latest')
def scan_latest():
    """Scan all :latest versions from ACR registries for comparison analysis"""
    config = load_config()
    
    console.print("🔍 Scanning ACR :latest images for fix comparison...")
    
    # Collect all ACR inventory files across environments
    latest_images = []
    processed_registries = set()
    
    for env_name, env_config in config['environments'].items():
        for reg_name, acr_config in env_config['acrs'].items():
            if reg_name not in processed_registries:
                inventory_file = acr_config['inventory_file']
                if Path(inventory_file).exists():
                    console.print(f"  📋 Loading {reg_name}: {inventory_file}")
                    with open(inventory_file, 'r') as f:
                        images = [line.strip() for line in f if line.strip()]
                        # Filter to only :latest images
                        latest_only = [img for img in images if img.endswith(':latest')]
                        latest_images.extend(latest_only)
                        console.print(f"     Found {len(latest_only)} :latest images")
                processed_registries.add(reg_name)
    
    if not latest_images:
        console.print("❌ No :latest images found in ACR inventories")
        console.print(f"💡 Run: {get_script_name()} inventory acr")
        return
    
    console.print(f"📊 Total :latest images to scan: {len(latest_images)}")
    console.print("📁 Output: sbom_reports/latest/")
    console.print("⚠️  This may take several minutes")
    
    # Process latest images
    _scan_acr_latest_images(config)

@scan.command('all')
@click.option('--env', type=click.Choice(['dev', 'prod']), help='Scan specific environment only (default: scan both dev and prod)')
@click.option('--input-file', help='Custom .txt file with image list (overrides other options)')
def scan_all(env, input_file):
    """Complete vulnerability scanning - scans AKS environments (not ACR latest)"""
    config = load_config()
    
    if input_file:
        # Custom input file mode - single scan
        if not Path(input_file).exists():
            console.print(f"❌ Input file not found: {input_file}")
            return
        environments_to_scan = [('custom', input_file)]
    elif env:
        # Single environment mode
        environments_to_scan = [(env, None)]
    else:
        # Default: scan ALL environments and ALL repositories
        environments_to_scan = [('dev', None), ('prod', None)]
    
    # Process each environment in the scan list
    for env_name, custom_file in environments_to_scan:
        if custom_file:
            # Custom input file mode
            console.print(f"\n🔍 Starting custom vulnerability analysis...")
            console.print(f"📋 Input: {custom_file}")
            output_dir = "custom"
            
            # Count images
            with open(custom_file, 'r') as f:
                image_count = len([line for line in f if line.strip()])
            
            console.print(f"📊 Target images: {image_count}")
            console.print(f"📁 Output: sbom_reports/{output_dir}/")
            console.print("⚠️  This may take several minutes")
                
            # Process the custom file
            _process_scan_custom(custom_file, output_dir, image_count)
            
        else:
            # Environment-based mode - scan AKS environment only
            env_config = config['environments'][env_name]
            console.print(f"\n🔍 Starting {env_config['name']} environment vulnerability analysis...")
            console.print("🔄 Scanning AKS deployed images")
            
            # Get AKS inventory file for the environment
            inventory_files = []
            inventory_files.append(env_config['aks']['inventory_file'])
            
            # Count total images across all repositories
            image_count = 0
            missing_inventories = []
            for inv_file in inventory_files:
                if Path(inv_file).exists():
                    with open(inv_file, 'r') as f:
                        count = len([line for line in f if line.strip()])
                        image_count += count
                        console.print(f"  📋 {Path(inv_file).name}: {count} images")
                else:
                    missing_inventories.append(inv_file)
            
            if missing_inventories:
                console.print("⚠️  Missing inventory files:")
                for missing in missing_inventories:
                    console.print(f"     - {missing}")
                console.print(f"💡 Run: {get_script_name()} inventory generate --env all")
                console.print()
            
            output_dir = config['scan_output']['environments'][env_name]
            console.print(f"📊 Target images: {image_count}")
            console.print(f"📁 Output: sbom_reports/{output_dir}/")
            console.print("⚠️  This may take several minutes")
                
            # Process the environment files
            _process_scan_environment(env_name, inventory_files, output_dir, image_count, config)
    
    # After processing environments, also scan ACR latest images if scanning all environments
    if not input_file and not env:
        console.print(f"\n🔍 Starting ACR latest images scan for comparison...")
        _scan_acr_latest_images(config)
        
        # After scanning everything, generate comparison reports
        console.print("\n📊 Generating vulnerability comparison reports...")
        _generate_detailed_comparison()

def _process_scan_custom(input_file, output_dir, image_count):
    """Process vulnerability scanning for a custom input file"""
    try:
        # Step 1: Create output directories
        console.print("📋 Step 1: Preparing output directories")
        subprocess.run(['mkdir', '-p', f'sbom_reports/{output_dir}', f'reports/{output_dir}'], check=True)
        
        # Step 2: Generate SBOMs with Trivy
        console.print("📋 Step 2: Generating SBOMs with Trivy")
        success_count = 0
        current = 0
        
        with open(input_file, 'r') as f:
            for line in f:
                image = line.strip()
                if not image:
                    continue
                
                current += 1
                console.print(f"[{current}/{image_count}] Scanning: {image}")
                
                safe_name = image.replace('/', '__').replace(':', '__')
                sbom_file = f"sbom_reports/{output_dir}/{safe_name}.json"
                
                if Path(sbom_file).exists():
                    console.print(f"  → Already exists: {sbom_file}")
                    success_count += 1
                    continue
                
                result = subprocess.run([
                    'trivy', 'image', '--scanners', 'vuln,license', 
                    '-q', '-f', 'cyclonedx', '-o', sbom_file, image
                ], capture_output=True)
                
                if result.returncode == 0:
                    console.print(f"  → Success: {sbom_file}")
                    success_count += 1
                else:
                    console.print(f"  → Failed: {image}")
                    Path(sbom_file).unlink(missing_ok=True)
        
        console.print(f"📊 SBOM generation complete: {success_count} successful")
        console.print(f"📊 SBOM reports available: sbom_reports/{output_dir}/")
        
        # Step 2.5: Extract OS information from generated SBOMs (ultra-fast!)
        if success_count > 0:
            console.print("\n📋 Step 2.5: Extracting OS versions from SBOMs")
            os_versions_csv = f"reports/{output_dir}/os_versions.csv"
            sbom_dir = f"sbom_reports/{output_dir}"
            _run_os_analysis_from_sboms(sbom_dir, os_versions_csv)
        
        # Step 3: Generate CSV reports from SBOMs
        if success_count > 0:
            console.print("\n📋 Step 3: Generating CSV reports")
            _generate_csv_reports(output_dir, output_dir)
        
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Scan failed: {e}")
    except Exception as e:
        console.print(f"❌ Error during scan: {e}")

def _generate_csv_reports(sbom_dir, output_dir):
    """Generate CSV reports from SBOM files"""
    try:
        # Check if SBOM directory has files
        sbom_path = Path(f'sbom_reports/{sbom_dir}')
        if not sbom_path.exists():
            console.print(f"⚠️  No SBOM directory found: {sbom_path}")
            return False
            
        sbom_files = list(sbom_path.glob('*.json'))
        if not sbom_files:
            console.print(f"⚠️  No SBOM files found in: {sbom_path}")
            return False
        
        console.print(f"  📊 Processing {len(sbom_files)} SBOM files...")
        
        # Generate tracking CSV using process_multiple_sboms.sh
        tracking_csv = f"reports/{output_dir}/vulnerabilities_tracking.csv"
        result = subprocess.run([
            './process_multiple_sboms.sh',
            f'sbom_reports/{sbom_dir}',
            tracking_csv
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            console.print(f"  ⚠️  Failed to generate tracking CSV: {result.stderr}")
            return False
        
        # Generate summary CSV
        summary_csv = f"reports/{output_dir}/vulnerabilities_summary.csv"
        result = subprocess.run([
            'python3', 'generate_summary.py',
            tracking_csv, summary_csv
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print(f"  ✅ Generated: {tracking_csv}")
            console.print(f"  ✅ Generated: {summary_csv}")
            return True
        else:
            console.print(f"  ⚠️  Failed to generate summary: {result.stderr}")
            return False
            
    except Exception as e:
        console.print(f"  ⚠️  Error generating CSV reports: {e}")
        return False

def _scan_acr_latest_images(config):
    """Scan all ACR :latest images and put them in sbom_reports/latest/"""
    console.print("🔍 Collecting ACR :latest images for comparison...")
    
    # Collect all ACR inventory files across environments
    latest_images = []
    processed_registries = set()
    
    for env_name, env_config in config['environments'].items():
        for reg_name, acr_config in env_config['acrs'].items():
            if reg_name not in processed_registries:
                inventory_file = acr_config['inventory_file']
                if Path(inventory_file).exists():
                    console.print(f"  📋 Loading {reg_name}: {inventory_file}")
                    with open(inventory_file, 'r') as f:
                        images = [line.strip() for line in f if line.strip()]
                        # Filter to only :latest images
                        latest_only = [img for img in images if img.endswith(':latest')]
                        latest_images.extend(latest_only)
                        console.print(f"     Found {len(latest_only)} :latest images")
                processed_registries.add(reg_name)
    
    if not latest_images:
        console.print("❌ No :latest images found in ACR inventories")
        console.print(f"💡 Run: {get_script_name()} inventory acr")
        return
    
    console.print(f"📊 Total :latest images to scan: {len(latest_images)}")
    console.print("📁 Output: sbom_reports/latest/")
    
    # Process latest images using the custom scan logic
    _process_scan_custom_with_images(latest_images, "latest")

def _process_scan_custom_with_images(images, output_dir):
    """Process vulnerability scanning for a list of images"""
    try:
        image_count = len(images)
        
        # Step 1: Create output directories
        console.print("📋 Step 1: Preparing output directories")
        subprocess.run(['mkdir', '-p', f'sbom_reports/{output_dir}', f'reports/{output_dir}'], check=True)
        
        # Step 2: Run Trivy vulnerability scans
        console.print("🔍 Step 2: Running Trivy vulnerability scans")
        success_count = 0
        
        for i, image in enumerate(images, 1):
            safe_filename = image.replace('/', '__').replace(':', '__') + '.json'
            output_file = f'sbom_reports/{output_dir}/{safe_filename}'
            
            console.print(f"[{i}/{image_count}] Scanning {image}...")
            
            # Skip if already exists
            if Path(output_file).exists():
                console.print(f"  → Already exists: {output_file}")
                success_count += 1
                continue
            
            try:
                subprocess.run([
                    'trivy', 'image', '--scanners', 'vuln,license', '-q', 
                    '-f', 'cyclonedx', '-o', output_file, image
                ], check=True, capture_output=True)
                console.print(f"  → Success: {output_file}")
                success_count += 1
            except subprocess.CalledProcessError as e:
                console.print(f"  ❌ Failed to scan {image}: {e}")
                # Remove failed output file if it exists
                Path(output_file).unlink(missing_ok=True)
                continue
            except Exception as e:
                console.print(f"  ❌ Error scanning {image}: {e}")
                # Remove failed output file if it exists  
                Path(output_file).unlink(missing_ok=True)
                continue
        
        console.print(f"📊 SBOM generation complete: {success_count} successful")
        console.print(f"📊 SBOM reports available: sbom_reports/{output_dir}/")
        
        # Step 2.5: Extract OS information from generated SBOMs (ultra-fast!)
        if success_count > 0:
            console.print("\n📋 Step 2.5: Extracting OS versions from SBOMs")
            os_versions_csv = f"reports/{output_dir}/os_versions.csv"
            sbom_dir = f"sbom_reports/{output_dir}"
            _run_os_analysis_from_sboms(sbom_dir, os_versions_csv)
        
        # Step 3: Generate CSV reports from SBOMs
        if success_count > 0:
            console.print("\n📋 Step 3: Generating CSV reports")
            _generate_csv_reports(output_dir, output_dir)
        
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Scan failed: {e}")
    except Exception as e:
        console.print(f"❌ Error during scan: {e}")

def _process_scan_environment(env_name, inventory_files, output_dir, image_count, config):
    """Process vulnerability scanning for an environment"""
    try:
        # Step 1: Create output directories
        console.print("📋 Step 1: Preparing output directories")
        subprocess.run(['mkdir', '-p', f'sbom_reports/{output_dir}', f'reports/{output_dir}'], check=True)
        
        # Step 2: Generate SBOMs with Trivy
        console.print("📋 Step 2: Generating SBOMs with Trivy")
        success_count = 0
        current = 0
        
        # Process environment inventory files
        for inv_file in inventory_files:
            if not Path(inv_file).exists():
                console.print(f"⚠️  Skipping missing inventory: {inv_file}")
                continue
            
            with open(inv_file, 'r') as f:
                for line in f:
                    image = line.strip()
                    if not image:
                        continue
                    
                    current += 1
                    console.print(f"[{current}/{image_count}] Scanning: {image}")
                    
                    safe_name = image.replace('/', '__').replace(':', '__')
                    sbom_file = f"sbom_reports/{output_dir}/{safe_name}.json"
                    
                    if Path(sbom_file).exists():
                        console.print(f"  → Already exists: {sbom_file}")
                        success_count += 1
                        continue
                    
                    result = subprocess.run([
                        'trivy', 'image', '--scanners', 'vuln,license', 
                        '-q', '-f', 'cyclonedx', '-o', sbom_file, image
                    ], capture_output=True)
                    
                    if result.returncode == 0:
                        console.print(f"  → Success: {sbom_file}")
                        success_count += 1
                    else:
                        console.print(f"  → Failed: {image}")
                        Path(sbom_file).unlink(missing_ok=True)
        
        console.print(f"📊 SBOM generation complete: {success_count} successful")
        console.print(f"📊 SBOM reports available: sbom_reports/{output_dir}/")
        
        # Step 2.5: Extract OS information from generated SBOMs (ultra-fast!)
        if success_count > 0:
            console.print("\n📋 Step 2.5: Extracting OS versions from SBOMs")
            os_versions_csv = f"reports/{output_dir}/os_versions.csv"
            sbom_dir = f"sbom_reports/{output_dir}"
            _run_os_analysis_from_sboms(sbom_dir, os_versions_csv)
        
        # Step 3: Generate CSV reports from SBOMs
        if success_count > 0:
            console.print("\n📋 Step 3: Generating CSV reports")
            _generate_csv_reports(output_dir, output_dir)
        
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Scan failed: {e}")
    except Exception as e:
        console.print(f"❌ Error during scan: {e}")

@cli.group()
def inventory():
    """Image inventory generation and management"""
    pass

@inventory.command('aks')
@click.option('--env', type=click.Choice(['prod', 'dev', 'all']), default='all', help='Environment to scan')
@click.option('--output', '-o', help='Custom output file path')
def inventory_aks(env, output):
    """Generate inventory of images currently running in AKS"""
    config = load_config()
    
    environments = []
    if env == 'all':
        environments = ['prod', 'dev']
    else:
        environments = [env]
    
    for env_name in environments:
        env_config = config['environments'][env_name]
        aks_config = env_config['aks']
        
        output_file = output or aks_config['inventory_file']
        
        console.print(f"🔍 Generating AKS inventory for {env_config['name']} environment...")
        console.print(f"📊 Output: {output_file}")
        
        try:
            # Switch to correct subscription and get credentials
            console.print(f"🔑 Getting credentials for {aks_config['cluster_name']}")
            subprocess.run(['az', 'account', 'set', '--subscription', aks_config['subscription']], check=True)
            subprocess.run(['az', 'aks', 'get-credentials', 
                          '--resource-group', aks_config['resource_group'],
                          '--name', aks_config['cluster_name'], 
                          '--overwrite-existing'], check=True)
            
            console.print("🔍 Querying running container images...")
            
            # Simple bash command to get all unique images
            cmd = f'''(kubectl get pods --all-namespaces -o jsonpath='{{range .items[*]}}{{.spec.containers[*].image}}{{"\\n"}}{{end}}'; kubectl get pods --all-namespaces -o jsonpath='{{range .items[*]}}{{.spec.initContainers[*].image}}{{"\\n"}}{{end}}') | sort -u | grep -v '^$' > {output_file}'''
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Count lines in output file
                with open(output_file, 'r') as f:
                    image_count = len([line for line in f if line.strip()])
                console.print(f"✅ {env_config['name']}: {image_count} unique container images")
                console.print(f"📋 Inventory saved to: {output_file}")
            else:
                console.print(f"❌ Failed to generate {env_name} AKS inventory: {result.stderr}")
                
        except subprocess.CalledProcessError as e:
            console.print(f"❌ Failed to get {env_name} AKS credentials: {e}")
        except Exception as e:
            console.print(f"❌ Error generating {env_name} AKS inventory: {e}")
        
        if len(environments) > 1:
            console.print()  # Add spacing between environments

@inventory.command('acr')
@click.option('--env', type=click.Choice(['prod', 'dev', 'all']), default='all', help='Environment to scan')
@click.option('--registry', '-r', help='Specific registry name')
@click.option('--output-dir', '-o', help='Output directory', default='.')
def inventory_acr(env, registry, output_dir):
    """Generate inventory of available images in ACR registries"""
    config = load_config()
    
    registries_to_process = []
    
    if registry:
        # Find specific registry across all environments
        for env_name, env_config in config['environments'].items():
            if registry in env_config['acrs']:
                acr_config = env_config['acrs'][registry]
                registries_to_process.append((registry, acr_config))
                break
        if not registries_to_process:
            console.print(f"❌ Registry {registry} not found in configuration")
            return
    else:
        # Process by environment, avoiding duplicates
        environments = []
        if env == 'all':
            environments = ['prod', 'dev']
        else:
            environments = [env]
        
        processed_registries = set()
        for env_name in environments:
            env_config = config['environments'][env_name]
            for reg_name, acr_config in env_config['acrs'].items():
                if reg_name not in processed_registries:
                    registries_to_process.append((reg_name, acr_config))
                    processed_registries.add(reg_name)
    
    console.print(f"🔍 Generating ACR inventory...")
    
    for reg_name, acr_config in registries_to_process:
        output_path = Path(output_dir) / acr_config['inventory_file']
        console.print(f"📋 Processing {reg_name} → {output_path}")
        
        try:
            # Use the simple bash command approach that we know works
            cmd = f'''az account set --subscription "{acr_config['subscription']}" && az acr repository list --name {acr_config['registry_name']} --output tsv | while read repo; do echo "{acr_config['registry_name']}.azurecr.io/$repo:latest"; done > {output_path}'''
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Count lines in output file
                with open(output_path, 'r') as f:
                    image_count = len([line for line in f if line.strip()])
                console.print(f"✅ {reg_name}: {image_count} images → {output_path}")
            else:
                console.print(f"❌ Failed to process {reg_name}: {result.stderr}")
            
        except Exception as e:
            console.print(f"❌ Error processing {reg_name}: {e}")

@inventory.command('all')
def inventory_all():
    """Generate all inventory files (AKS + ACR + master) at once"""
    console.print("🔍 Generating complete inventory for all environments...")
    console.print()
    
    # Call existing functions
    ctx = click.get_current_context()
    
    console.print("📋 Step 1: Generating AKS inventories")
    ctx.invoke(inventory_aks, env='all', output=None)
    console.print()
    
    console.print("📋 Step 2: Generating ACR inventories") 
    ctx.invoke(inventory_acr, env='all', registry=None, output_dir='.')
    console.print()
    
    console.print("📋 Step 3: Generating master inventory")
    ctx.invoke(inventory_master, output=None)
    console.print()
    
    console.print("🎉 Complete inventory generation finished!")
    console.print("📊 All inventory files have been updated and are ready for scanning")

@inventory.command('master')
@click.option('--output', '-o', help='Output file path')
def inventory_master(output):
    """Generate master inventory CSV combining all sources"""
    config = load_config()
    
    output_file = output or config['master_inventory']['output_file']
    console.print(f"🔍 Generating master inventory: {output_file}")
    
    master_entries = []
    total_count = 0
    
    for source_config in config['master_inventory']['sources']:
        filename = source_config['inventory_file']
        source_type = source_config['source_type']
        filepath = Path(filename)
        
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    images = [line.strip() for line in f if line.strip()]
                    for image in images:
                        master_entries.append(f"{source_type},{image}")
                    console.print(f"📋 {filename}: {len(images)} images ({source_type})")
                    total_count += len(images)
            except Exception as e:
                console.print(f"⚠️  Error reading {filename}: {e}")
        else:
            console.print(f"⚠️  Missing: {filename}")
    
    # Write master inventory
    try:
        with open(output_file, 'w') as f:
            f.write('\n'.join(master_entries) + '\n')
        console.print(f"✅ Master inventory: {total_count} total images → {output_file}")
    except Exception as e:
        console.print(f"❌ Failed to write master inventory: {e}")

@cli.group()
def reports():
    """Report generation and management"""
    pass

@reports.command('compare')
def compare_reports():
    """Generate detailed vulnerability comparison between production and latest images"""
    _generate_detailed_comparison()

@reports.command('generate')
@click.option('--env', type=click.Choice(['dev', 'prod', 'all']), help='Environment to process (processes SBOM directories)')
@click.option('--input-dir', help='Custom SBOM directory to process')
@click.argument('sbom_file', required=False)
def generate_reports(env, input_dir, sbom_file):
    """Generate all reports from SBOM data"""
    config = load_config()
    
    # Handle different modes: environment-based vs single file
    if env or input_dir:
        # Environment-based or custom directory processing
        return _process_sbom_directories(config, env, input_dir)
    elif sbom_file:
        # Single file processing (backward compatibility)
        return _process_single_sbom(sbom_file)
    else:
        # Default single file processing
        return _process_single_sbom('sbom.json')

def _process_single_sbom(sbom_file):
    """Process a single SBOM file (legacy mode)"""
    if not Path(sbom_file).exists():
        console.print(f"❌ SBOM file not found: {sbom_file}")
        return
    
    console.print(f"📊 Generating reports from: {sbom_file}")
    
    try:
        # Create reports directory
        subprocess.run(['mkdir', '-p', 'reports/analysis'], check=True)
        
        # Define report file paths in reports directory
        tracking_csv = 'reports/analysis/remediation_tracking.csv'
        summary_csv = 'reports/analysis/remediation_summary.csv'
        jira_md = 'reports/analysis/jira_epic.md'
        
        # Generate remediation CSV
        console.print("🔄 Generating remediation tracking CSV...")
        subprocess.run([
            'python3', 'generate_remediation_csv.py', 
            sbom_file, tracking_csv
        ], check=True)
        
        # Generate summary
        console.print("🔄 Generating summary CSV...")
        subprocess.run([
            'python3', 'generate_summary.py',
            tracking_csv, summary_csv
        ], check=True)
        
        # Generate Jira format
        console.print("🔄 Generating Jira epic...")
        subprocess.run([
            'python3', 'generate_jira_format.py',
            tracking_csv, jira_md
        ], check=True)
        
        console.print("✅ All reports generated successfully")
        console.print("📁 Files created:")
        console.print(f"  - {tracking_csv}")
        console.print(f"  - {summary_csv}")
        console.print(f"  - {jira_md}")
        
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Report generation failed: {e}")

def _process_sbom_directories(config, env, input_dir):
    """Process SBOM directories for environment-based analysis"""
    environments_to_process = []
    
    if input_dir:
        # Custom directory processing
        if not Path(input_dir).exists():
            console.print(f"❌ SBOM directory not found: {input_dir}")
            return
        environments_to_process = [('custom', input_dir)]
    else:
        # Environment-based processing
        if env == 'all':
            dev_dir = config['scan_output']['environments']['dev']
            prod_dir = config['scan_output']['environments']['prod']
            environments_to_process = [('dev', f'sbom_reports/{dev_dir}'), ('prod', f'sbom_reports/{prod_dir}')]
        elif env:
            output_dir = config['scan_output']['environments'].get(env, env)
            environments_to_process = [(env, f'sbom_reports/{output_dir}')]
        else:
            console.print("❌ Must specify --env or --input-dir")
            return
    
    for env_name, sbom_dir in environments_to_process:
        if not Path(sbom_dir).exists():
            console.print(f"⚠️  SBOM directory not found: {sbom_dir}")
            continue
            
        # Check if directory has SBOM files
        sbom_files = list(Path(sbom_dir).glob('*.json'))
        if not sbom_files:
            console.print(f"⚠️  No SBOM files found in: {sbom_dir}")
            continue
            
        console.print(f"📊 Processing {len(sbom_files)} SBOM files for {env_name}...")
        
        # Create output directory
        output_dir_path = f"reports/{env_name}"
        subprocess.run(['mkdir', '-p', output_dir_path], check=True)
        
        # Use process_multiple_sboms.sh logic
        output_csv = f"{output_dir_path}/vulnerabilities_tracking.csv"
        success = _run_batch_csv_generation(sbom_dir, output_csv)
        
        if success:
            # Generate summary
            summary_csv = f"{output_dir_path}/vulnerabilities_summary.csv"
            console.print(f"🔄 Generating {env_name} summary...")
            subprocess.run([
                'python3', 'generate_summary.py',
                output_csv, summary_csv
            ], check=True)
            
            console.print(f"✅ {env_name} reports generated:")
            console.print(f"  - {output_csv}")
            console.print(f"  - {summary_csv}")
        
        # Note: generate_detailed_comparison expects production/latest directories
        # We generate prod/ but comparison expects production/
        # So we'll run comparison separately after all processing

def _run_batch_csv_generation(sbom_dir, output_csv):
    """Run batch CSV generation using process_multiple_sboms.sh"""
    try:
        console.print(f"🔄 Using process_multiple_sboms.sh for: {sbom_dir}")
        
        # Use the existing process_multiple_sboms.sh script
        result = subprocess.run([
            './process_multiple_sboms.sh',
            sbom_dir,
            output_csv
        ], check=True, capture_output=True, text=True)
        
        console.print("✅ Batch CSV generation completed")
        return True
        
    except subprocess.CalledProcessError as e:
        console.print(f"❌ Batch CSV generation failed: {e}")
        if e.stdout:
            console.print(f"stdout: {e.stdout}")
        if e.stderr:
            console.print(f"stderr: {e.stderr}")
        return False
    except Exception as e:
        console.print(f"❌ Error running batch CSV generation: {e}")
        return False

def _generate_detailed_comparison():
    """Generate detailed vulnerability comparisons for both prod and dev vs latest"""
    try:
        console.print("\n📊 Generating detailed vulnerability comparisons...")
        
        # Check what data we have available
        have_prod = (Path('reports/production/vulnerabilities_summary.csv').exists() or 
                    Path('reports/prod/vulnerabilities_summary.csv').exists())
        have_dev = Path('reports/dev/vulnerabilities_summary.csv').exists()
        have_latest = Path('reports/latest/vulnerabilities_summary.csv').exists()
        
        if not have_latest:
            console.print("ℹ️  No latest image data available for comparison")
            return
        
        comparisons_generated = []
        
        # Generate Production vs Latest comparison (existing functionality)
        if have_prod:
            console.print("🏭 Production vs Latest comparison...")
            
            # Create symlinks if needed for compatibility with generate_detailed_comparison.py
            if not Path('reports/production').exists() and Path('reports/prod').exists():
                subprocess.run(['ln', '-s', 'prod', 'reports/production'], capture_output=True)
            
            # Run comparison analysis
            console.print("  🔄 Running comparison analysis...")
            subprocess.run(['python3', 'compare_vulnerabilities.py'], check=True)
            
            # Generate detailed comparison CSV
            console.print("  🔄 Generating detailed CSV...")
            result = subprocess.run(['python3', 'generate_detailed_comparison.py'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                comparisons_generated.append("Production vs Latest")
                console.print("  ✅ Production comparison files generated")
        
        # Generate Dev vs Latest comparison (new functionality)
        if have_dev:
            console.print("\n🧪 Dev vs Latest comparison...")
            
            # Backup production comparison files before running dev comparison
            if Path('reports/comparison/vulnerability_comparison_summary.txt').exists():
                subprocess.run(['cp', 'reports/comparison/vulnerability_comparison_summary.txt', 
                              'reports/comparison/vulnerability_comparison_summary_prod_backup.txt'], capture_output=True)
            if Path('reports/comparison/detailed_vulnerability_comparison.csv').exists():
                subprocess.run(['cp', 'reports/comparison/detailed_vulnerability_comparison.csv', 
                              'reports/comparison/detailed_vulnerability_comparison_prod_backup.csv'], capture_output=True)
            
            # Temporarily backup existing production symlink if it exists
            prod_symlink_existed = Path('reports/production').exists()
            if prod_symlink_existed:
                subprocess.run(['mv', 'reports/production', 'reports/production_backup'], capture_output=True)
            
            # Create temporary symlink for dev comparison
            subprocess.run(['ln', '-s', 'dev', 'reports/production'], capture_output=True)
            
            # Run comparison analysis
            console.print("  🔄 Running comparison analysis...")
            subprocess.run(['python3', 'compare_vulnerabilities.py'], check=True)
            
            # Generate detailed comparison CSV
            console.print("  🔄 Generating detailed CSV...")
            result = subprocess.run(['python3', 'generate_detailed_comparison.py'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                # Rename files to dev-specific names (only if they exist)
                if Path('reports/comparison/vulnerability_comparison_summary.txt').exists():
                    subprocess.run(['mv', 'reports/comparison/vulnerability_comparison_summary.txt', 
                                  'reports/comparison/vulnerability_comparison_summary_dev.txt'], capture_output=True)
                if Path('reports/comparison/detailed_vulnerability_comparison.csv').exists():
                    subprocess.run(['mv', 'reports/comparison/detailed_vulnerability_comparison.csv', 
                                  'reports/comparison/detailed_vulnerability_comparison_dev.csv'], capture_output=True)
                comparisons_generated.append("Dev vs Latest")
                console.print("  ✅ Dev comparison files generated")
            
            # Restore original production symlink
            subprocess.run(['rm', 'reports/production'], capture_output=True)
            if prod_symlink_existed:
                subprocess.run(['mv', 'reports/production_backup', 'reports/production'], capture_output=True)
            
            # Restore production comparison files
            if Path('reports/comparison/vulnerability_comparison_summary_prod_backup.txt').exists():
                subprocess.run(['mv', 'reports/comparison/vulnerability_comparison_summary_prod_backup.txt', 
                              'reports/comparison/vulnerability_comparison_summary.txt'], capture_output=True)
            if Path('reports/comparison/detailed_vulnerability_comparison_prod_backup.csv').exists():
                subprocess.run(['mv', 'reports/comparison/detailed_vulnerability_comparison_prod_backup.csv', 
                              'reports/comparison/detailed_vulnerability_comparison.csv'], capture_output=True)
        
        if comparisons_generated:
            console.print("\n✅ Comparison analysis complete!")
            console.print("📋 Generated reports:")
            
            if "Production vs Latest" in comparisons_generated:
                console.print("  📊 Production vs Latest:")
                console.print("    - reports/comparison/vulnerability_comparison_summary.txt")
                console.print("    - reports/comparison/detailed_vulnerability_comparison.csv")
            
            if "Dev vs Latest" in comparisons_generated:
                console.print("  📊 Dev vs Latest:")
                console.print("    - reports/comparison/vulnerability_comparison_summary_dev.txt") 
                console.print("    - reports/comparison/detailed_vulnerability_comparison_dev.csv")
                
            console.print("\n💡 The detailed CSVs show package-level status:")
            console.print("  - FIXED: Vulnerabilities resolved in latest")
            console.print("  - NEW: New vulnerabilities in latest")
            console.print("  - IMPROVED/WORSENED/UNCHANGED: Package status changes")
            
            # Generate Excel workbook if pandas is available
            console.print("\n📊 Generating Excel workbook...")
            try:
                result = subprocess.run(['python3', 'generate_excel_comparison.py'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    console.print("  ✅ Excel workbook created: reports/vulnerability_comparison_analysis.xlsx")
                else:
                    console.print("  ℹ️  Excel generation skipped (pandas/openpyxl not installed)")
            except Exception:
                console.print("  ℹ️  Excel generation skipped (pandas/openpyxl not available)")
        else:
            console.print("⚠️  No comparisons could be generated")
        
    except subprocess.CalledProcessError as e:
        console.print(f"⚠️  Could not generate comparison: {e}")
    except Exception as e:
        console.print(f"⚠️  Error generating comparison: {e}")

if __name__ == "__main__":
    cli()