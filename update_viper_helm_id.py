#!/usr/bin/env python3
"""
Update Viper device group with Helm SBOM ID (product version UUID).
"""

import sys
import os
from helm_viper_integration import update_viper_device_group, load_api_keys


def main():
    """Update Viper device group with Helm product version UUID."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Update Viper device group with Helm SBOM ID',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update device group with Helm product version UUID
  %(prog)s --device-group-id cxxxxxxxxxxxxxxxxxxxxxxxx --helm-sbom-id 00000000-0000-0000-0000-000000000000
"""
    )

    parser.add_argument('--device-group-id', required=True,
                       help='Viper device group ID')
    parser.add_argument('--helm-sbom-id', required=True,
                       help='Helm product version UUID (SBOM ID)')

    args = parser.parse_args()

    # Load Viper API key
    _, _, viper_key = load_api_keys()

    if not viper_key:
        print("✗ Error: Viper API key not found in viper_api_key.txt")
        return 1

    print("=" * 70)
    print("Updating Viper Device Group with Helm SBOM ID")
    print("=" * 70)
    print(f"\nDevice Group ID: {args.device_group_id}")
    print(f"Helm SBOM ID: {args.helm_sbom_id}")
    print()

    # Update device group
    result = update_viper_device_group(
        args.device_group_id,
        args.helm_sbom_id,
        viper_key
    )

    if result.get('success'):
        print("=" * 70)
        print("✓ Success!")
        print("=" * 70)
        print(f"\nDevice group '{args.device_group_id}' updated with Helm SBOM ID '{args.helm_sbom_id}'")
        if result.get('response'):
            print(f"\nViper API Response:")
            import json
            print(json.dumps(result['response'], indent=2))
        return 0
    else:
        print("=" * 70)
        print("✗ Failed")
        print("=" * 70)
        print(f"\nError: {result.get('error')}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
