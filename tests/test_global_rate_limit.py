#!/usr/bin/env python3
"""
Test script to demonstrate global rate limiting.
Sends requests rapidly to trigger the global rate limit.
"""

import time
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

def test_global_rate_limit(server_url="http://localhost:8000", num_requests=120):
    """
    Test global rate limiting by sending many requests quickly.

    With default settings (100 requests/minute globally),
    requests 101+ should be rejected.
    """

    print(f"Testing global rate limit with {num_requests} requests...")
    print(f"Server: {server_url}")
    print(f"Expected: First 100 succeed, then rate limited")
    print("=" * 70)

    success_count = 0
    rate_limited_count = 0
    errors = 0

    start_time = time.time()

    for i in range(1, num_requests + 1):
        try:
            req = Request(f"{server_url}/health")
            with urlopen(req) as response:
                if response.status == 200:
                    success_count += 1
                    if i % 10 == 0:
                        data = json.loads(response.read().decode())
                        available = data.get('global_rate_limit', {}).get('available', 'N/A')
                        print(f"Request {i:3d}: ✓ Success (Available: {available})")
                else:
                    print(f"Request {i:3d}: Unexpected status {response.status}")

        except HTTPError as e:
            if e.code == 429:
                rate_limited_count += 1
                try:
                    error_data = json.loads(e.read().decode())
                    if i == 101 or i % 10 == 0:  # Print first rate limit and every 10th
                        print(f"Request {i:3d}: ⚠ Rate Limited - {error_data.get('message', 'Too many requests')}")
                except:
                    print(f"Request {i:3d}: ⚠ Rate Limited (429)")
            else:
                errors += 1
                print(f"Request {i:3d}: ✗ HTTP Error {e.code}")

        except URLError as e:
            errors += 1
            if i == 1:
                print(f"✗ ERROR: Cannot connect to server at {server_url}")
                print("Make sure the server is running!")
                return

        # Small delay to avoid overwhelming the system
        time.sleep(0.01)

    elapsed_time = time.time() - start_time

    print("=" * 70)
    print("Test Results:")
    print(f"  Total requests sent: {num_requests}")
    print(f"  Successful: {success_count}")
    print(f"  Rate limited (429): {rate_limited_count}")
    print(f"  Other errors: {errors}")
    print(f"  Time elapsed: {elapsed_time:.2f} seconds")
    print(f"  Request rate: {num_requests / elapsed_time:.1f} req/sec")
    print()

    if rate_limited_count > 0:
        print("✓ Global rate limiting is working!")
        print(f"  Requests 1-100 succeeded, then rate limiting kicked in")
    else:
        print("⚠ No rate limiting detected - server may need adjustment")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Test global rate limiting')
    parser.add_argument('--url', default='http://localhost:8000',
                       help='Server URL (default: http://localhost:8000)')
    parser.add_argument('--requests', type=int, default=120,
                       help='Number of requests to send (default: 120)')

    args = parser.parse_args()

    test_global_rate_limit(args.url, args.requests)
