import argparse
import sys
import time
from timeit import default_timer as timer
from multiprocessing import Process

import boto3
import requests
from botocore.config import Config
import tempfile
import subprocess

config = Config(retries=dict(max_attempts=10))

# TODO: remove global variables
# TODO: take ip list filename from args
# TODO: change exception handling

with open("ip_list") as f:
    ip_list = [line.strip() for line in f.readlines()]

DESCRIPTION = r"""                      
                   __                __
   ________  _____/ /___  __  ______/ /
  / ___/ _ \/ ___/ / __ \/ / / / __  / 
 / /  /  __/ /__/ / /_/ / /_/ / /_/ /  
/_/   \___/\___/_/\____/\__,_/\__,_/   
"""

TATAL_CYCLES = 0
CYCLES = 0
TOTAL_TIME = 0
UNIQUE_ADDRESSES = []

AWSRegions = [
    "us-east-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
]


def check_ip_by_region(region):
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    data = requests.get(url).json()
    cidr_of_region = [k["ip_prefix"] for k in data["prefixes"] if k["region"] == region]

    networks = tempfile.NamedTemporaryFile("w")
    networks.writelines([line + "\n" for line in cidr_of_region])
    networks.seek(0)

    r = subprocess.check_output(
        [
            "go",
            "run",
            "check_range.go",
            "-network_file",
            networks.name,
            "-ip_file",
            "ip_list",
        ]
    )
    return r.decode("utf-8").splitlines()


def main(args):
    global TATAL_CYCLES, CYCLES, TOTAL_TIME, UNIQUE_ADDRESSES

    engine = boto3.client(
        "ec2",
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
        region_name=args.region,
        config=config,
    )
    print(
        "\n[+] Connected to AWS. Hunting in {} ... (max: {})\n".format(
            args.region, args.count
        )
    )

    TATAL_CYCLES += args.count
    for _ in range(args.count):
        start = timer()

        for _ in range(3):
            try:
                eip = engine.allocate_address(Domain="vpc")
                break
            except Exception:
                time.sleep(1)
                print("Allocate exception", end="\r")

        address = eip["PublicIp"]
        allocation_id = eip["AllocationId"]
        
        if address not in UNIQUE_ADDRESSES:
            UNIQUE_ADDRESSES.append(address)
            if address in ip_list:
                print("\t Hooray, the ip is in the list: {}".format(address))
                break

        for _ in range(3):
            try:
                engine.release_address(AllocationId=allocation_id)
                break
            except Exception:
                time.sleep(1)
                print("Release exception", end="\r")
        
        end = timer()

        TOTAL_TIME += end - start
        CYCLES += 1

        print(f"\t- Time: {TOTAL_TIME / CYCLES}, Ratio: {len(UNIQUE_ADDRESSES) / CYCLES}, Progress: {CYCLES}/{TATAL_CYCLES}", end="\r")

    print("\n")


if __name__ == "__main__":
    print(DESCRIPTION)

    parser = argparse.ArgumentParser(
        description=DESCRIPTION, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("region", choices=AWSRegions, help="AWS Region to search")
    parser.add_argument(
        "-c", "--count", type=int, help="Number of IPs to try", default=10000
    )
    parser.add_argument(
        "-p", "--processes", type=int, help="Amount of processes", default=5
    )
    parser.add_argument("-aK", "--access-key", help="AWS access key")
    parser.add_argument("-sK", "--secret-key", help="AWS secret key")

    args = parser.parse_args(sys.argv[1:])
    ip_list = check_ip_by_region(args.region)

    print(f"Length of ip list is: {len(ip_list)}")

    procs = []
    for _ in range(args.processes):
        proc = Process(target=main, args=(args,))
        procs.append(proc)
        proc.start()
        time.sleep(1)

    for proc in procs:
        proc.join()
