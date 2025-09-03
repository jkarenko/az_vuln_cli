#!/usr/bin/env bash
# Configuration functions for az_vuln_cli
# Source this file in bash scripts to use environment configuration

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to get ACR information for an environment
# Usage: get_acr_info "prod" 
# Returns: Each ACR info on separate line in format: "acr_name:subscription:registry_name"
get_acr_info() {
    local env_name="$1"
    if [ -z "$env_name" ]; then
        echo "ERROR: Environment name required" >&2
        return 1
    fi
    
    python3 "$SCRIPT_DIR/config_parser.py" --acr-info "$env_name"
}

# Function to get AKS information for an environment  
# Usage: get_aks_info "prod"
# Returns: "subscription:resource_group:cluster_name:inventory_file"
get_aks_info() {
    local env_name="$1"
    if [ -z "$env_name" ]; then
        echo "ERROR: Environment name required" >&2
        return 1
    fi
    
    python3 "$SCRIPT_DIR/config_parser.py" --aks-info "$env_name"
}

# Function to get a specific configuration value
# Usage: get_config_value "environments.prod.aks.subscription"
get_config_value() {
    local path="$1"
    if [ -z "$path" ]; then
        echo "ERROR: Configuration path required" >&2
        return 1
    fi
    
    python3 "$SCRIPT_DIR/config_parser.py" --get "$path"
}

# Function to list all available environments
# Usage: list_environments
list_environments() {
    python3 "$SCRIPT_DIR/config_parser.py" --list-envs
}

# Function to authenticate with ACR registries for an environment
# Usage: auth_acr_environment "prod"
auth_acr_environment() {
    local env_name="$1"
    if [ -z "$env_name" ]; then
        echo "ERROR: Environment name required" >&2
        return 1
    fi
    
    echo "=== Authenticating with ACR Registries for $env_name environment ==="
    
    local success_count=0
    local failed_registries=()
    
    # Get ACR information and loop through each registry
    while IFS=':' read -r acr_name subscription registry_name; do
        if [ -z "$acr_name" ]; then
            continue  # Skip empty lines
        fi
        
        echo "Logging into $registry_name ($subscription)..."
        if az account set --subscription "$subscription" && az acr login --name "$registry_name"; then
            echo "✅ $registry_name login successful"
            ((success_count++))
        else
            echo "❌ Failed to login to $registry_name"
            failed_registries+=("$registry_name")
        fi
        echo ""
    done < <(get_acr_info "$env_name")
    
    if [ "$success_count" -eq 0 ]; then
        echo "❌ Failed to authenticate with any ACR registries"
        return 1
    elif [ ${#failed_registries[@]} -gt 0 ]; then
        echo "⚠️  Some registries failed: ${failed_registries[*]}"
        return 1
    else
        echo "✅ All ACR registries authenticated successfully"
        return 0
    fi
}

# Function to get inventory file by source type (dynamic from YAML)
# Usage: get_inventory_by_source_type "ACR-PROD" ["prod"]
get_inventory_by_source_type() {
    local source_type="$1"
    local env_filter="$2"  # Optional environment filter
    
    if [ -z "$source_type" ]; then
        echo "ERROR: Source type required" >&2
        return 1
    fi
    
    if [ -n "$env_filter" ]; then
        python3 "$SCRIPT_DIR/config_parser.py" --inventory-by-source "$source_type" --env "$env_filter"
    else
        python3 "$SCRIPT_DIR/config_parser.py" --inventory-by-source "$source_type"
    fi
}

# Function to get inventory file for specific source type and environment
# Usage: get_inventory_file "prod" "AKS"
get_inventory_file() {
    local env_name="$1"
    local source_type="$2"
    
    if [ -z "$env_name" ] || [ -z "$source_type" ]; then
        echo "ERROR: Environment name and source type required" >&2
        return 1
    fi
    
    case "$source_type" in
        "AKS")
            # For AKS, still use the direct environment lookup since it's environment-specific
            get_config_value "environments.$env_name.aks.inventory_file"
            ;;
        "AKS-DEV")
            # Use the dynamic lookup for dev AKS
            get_inventory_by_source_type "$source_type" "$env_name"
            ;;
        "ACR-"*)
            # Use the dynamic lookup for all ACR source types
            get_inventory_by_source_type "$source_type" "$env_name"
            ;;
        *)
            echo "ERROR: Unknown source type: $source_type" >&2
            return 1
            ;;
    esac
}
