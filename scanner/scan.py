import os
import sys

def scan(target):
    result = os.system(f"echo Exploiting {target}")
    return result

if __name__ == '__main__':
    target = sys.argv[1]
    print(scan(target))
