import os
import subprocess

def scan(target):
    result = subprocess.run(['./scanner/scan.py', target], capture_output=True, text=True)
    return result.stdout.strip()

if __name__ == '__main__':
    target = os.getenv('TARGET')
    if target:
        impact = os.getenv('IMPACT')
        if impact:
            print(f"Target: {target}, Impact: {impact}")
            print(scan(target))
        else:
            print(f"Target: {target}")
            print(scan(target))
    else:
        print("No target provided.")
