import os
import json
import pandas as pd
from ipwhois import IPWhois

def main():
    df = pd.read_csv('input.csv')
    ip_cache_file = "cache.json"

    # Load cache from disk.
    # Allows cache to persist between runs.
    if os.path.exists(ip_cache_file):
        with open(ip_cache_file, 'r') as f:
            ip_cache = json.load(f)
        print(f"Loaded {len(ip_cache)} cached IP entries.")
    else:
        ip_cache = {}

    print("Starting log search and IP lookup...")

    # Function to lookup IP ownership
    def get_ip_owner(ip):
        print(ip)
        if ip in ip_cache:
            print(ip_cache[ip])
            return ip_cache[ip]
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(asn_methods=["whois"])
            owner = res.get('network', {}).get('name') or res.get('asn_description')
            ip_cache[ip] = owner
            print(ip_cache[ip])
            return owner
        except Exception as e:
            ip_cache[ip] = f"Error: {e}"
            print(ip_cache[ip])
            return ip_cache[ip]

    # Extract destination IP from log
    def extract_dst_ip(log_entry):
        try:
            return log_entry.split('dst_ip=')[1].split(',')[0].strip()
        except IndexError:
            return None

    df['dst_ip'] = df['log'].apply(extract_dst_ip)
    df['dst_ip_owner'] = df['dst_ip'].apply(lambda ip: get_ip_owner(ip) if ip else "Invalid IP")
    df.to_csv('output_with_owners.csv', index=False)
    print("IP ownership lookup completed. Results saved in output_with_owners.csv")

    # Write cache to disk.
    with open(ip_cache_file , 'w') as f:
        json.dump(ip_cache, f, indent=2)
    print(f"IP cache saved to {ip_cache_file}")

if __name__ == "__main__":
    main()