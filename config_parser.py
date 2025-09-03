#!/usr/bin/env python3
"""
Configuration parser utility for az_vuln_cli
Extracts values from environments.yaml for use in bash scripts
"""

import sys
import yaml
import argparse
from pathlib import Path


def load_config():
    """Load environment configuration from environments.yaml"""
    config_path = Path('environments.yaml')
    if not config_path.exists():
        print("ERROR: environments.yaml not found", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"ERROR: Loading environments.yaml: {e}", file=sys.stderr)
        sys.exit(1)


def get_acr_info(env_name):
    """Get all ACR information for an environment"""
    config = load_config()
    
    if env_name not in config['environments']:
        print(f"ERROR: Environment '{env_name}' not found", file=sys.stderr)
        sys.exit(1)
    
    env_config = config['environments'][env_name]
    acrs = env_config.get('acrs', {})
    
    result = []
    for acr_name, acr_config in acrs.items():
        result.append(f"{acr_name}:{acr_config['subscription']}:{acr_config['registry_name']}")
    
    return result


def get_aks_info(env_name):
    """Get AKS information for an environment"""
    config = load_config()
    
    if env_name not in config['environments']:
        print(f"ERROR: Environment '{env_name}' not found", file=sys.stderr)
        sys.exit(1)
    
    env_config = config['environments'][env_name]
    aks = env_config.get('aks', {})
    
    if not aks:
        print(f"ERROR: No AKS configuration found for environment '{env_name}'", file=sys.stderr)
        sys.exit(1)
    
    return f"{aks['subscription']}:{aks['resource_group']}:{aks['cluster_name']}:{aks['inventory_file']}"


def get_specific_value(path):
    """Get a specific value using dot notation (e.g., 'environments.prod.aks.subscription')"""
    config = load_config()
    
    keys = path.split('.')
    current = config
    
    try:
        for key in keys:
            current = current[key]
        return str(current)
    except (KeyError, TypeError):
        print(f"ERROR: Path '{path}' not found in configuration", file=sys.stderr)
        sys.exit(1)


def get_inventory_by_source_type(source_type, env_name=None):
    """Get inventory file for a specific source type and optional environment"""
    config = load_config()
    
    sources = config.get('master_inventory', {}).get('sources', [])
    
    for source in sources:
        if source.get('source_type') == source_type:
            # If env_name is specified, must match
            if env_name and source.get('env') != env_name:
                continue
            # If no env_name specified, take the first match
            return source.get('inventory_file', '')
    
    print(f"ERROR: Source type '{source_type}' not found in configuration", file=sys.stderr)
    if env_name:
        print(f"       (with environment '{env_name}')", file=sys.stderr)
    sys.exit(1)


def list_environments():
    """List all available environments"""
    config = load_config()
    return list(config['environments'].keys())


def main():
    parser = argparse.ArgumentParser(description='Extract configuration values from environments.yaml')
    parser.add_argument('--acr-info', help='Get ACR information for environment')
    parser.add_argument('--aks-info', help='Get AKS information for environment')
    parser.add_argument('--get', help='Get specific value using dot notation')
    parser.add_argument('--inventory-by-source', help='Get inventory file by source type')
    parser.add_argument('--env', help='Environment filter for --inventory-by-source')
    parser.add_argument('--list-envs', action='store_true', help='List all environments')
    
    args = parser.parse_args()
    
    if args.list_envs:
        envs = list_environments()
        for env in envs:
            print(env)
    elif args.acr_info:
        acr_info = get_acr_info(args.acr_info)
        for info in acr_info:
            print(info)
    elif args.aks_info:
        aks_info = get_aks_info(args.aks_info)
        print(aks_info)
    elif args.get:
        value = get_specific_value(args.get)
        print(value)
    elif args.inventory_by_source:
        inventory_file = get_inventory_by_source_type(args.inventory_by_source, args.env)
        print(inventory_file)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
