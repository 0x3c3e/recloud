import argparse
import re
import sys
import time
from multiprocessing import Process

import boto3
import dns.resolver
import requests
import tldextract
from botocore.config import Config
from netaddr import IPAddress, IPNetwork

config = Config(retries=dict(max_attempts=10))

domains = []
blacklist = [
    "amazonaws.com",
    "dynu.com",
    "bona.com",
    "splunkcloud.com",
    "elasticbeanstalk.com",
    "openvpn.net",
    "cisco.com",
]

with open("ip_list") as f:
    ip_list = [line.strip() for line in f.readlines()]

with open("domains.txt") as f:
    for line in f:
        domain = line.strip()
        if domain not in blacklist:
            domains.append(domain)

Description = """                      
 _____ _           _ _____                     
|     | |___ _ _ _| | __  |___ ___ ___ ___ ___ 
|   --| | . | | | . |    -| .'|  _| . | . |   |
|_____|_|___|___|___|__|__|__,|___|___|___|_|_|
    Cloud IP Hunting - Proof of Concept [AWS]         
"""

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

Session = None
CSRFToken = None


def get_hostnames(address):
    global Session
    global CSRFToken

    if not Session:
        Session = requests.Session()
        response = Session.get("https://securitytrails.com/list/ip/1.1.1.1")
        CSRFToken = re.findall(r'csrf_token = "(\S+?)"', response.text)[0]

    response = Session.post(
        f"https://securitytrails.com/app/api/v1/list?ipv4={address}",
        json={"_csrf_token": CSRFToken},
    )

    if response.status_code != 200:
        print("[!] SecurityTrails request failed!")
        time.sleep(2)
        raise ValueError

    records = response.json().pop("records", [])

    if records:
        return [r["hostname"] for r in records]

    return []


def check_ip(hostname):
    try:
        return dns.resolver.query(hostname, "A")
    except Exception:
        return []


def filter_ips_by_region(region):
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    data = requests.get(url).json()
    cidr_of_region = [k["ip_prefix"] for k in data["prefixes"] if k["region"] == region]
    result = []

    for ip in ip_list:
        for ip_cidr in cidr_of_region:
            if IPAddress(ip) in IPNetwork(ip_cidr):
                result.append(result)
                break
    return result


def main(args):
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

    for _ in range(args.count):

        for _ in range(3):
            try:
                eip = engine.allocate_address(Domain="vpc")
                break
            except Exception:
                time.sleep(1)
                print("Allocate exception")

        address = eip["PublicIp"]
        allocation_id = eip["AllocationId"]

        if address in ip_list:
            print("\tHooray, the ip is in the list: {}".format(address))
            break

        for _ in range(3):
            try:
                hostnames = get_hostnames(address)
                break
            except Exception:
                hostnames = []
                print("Issues with trails")
                time.sleep(1)

        if hostnames:
            whitelist_tld = [
                hostname
                for hostname in hostnames
                if ".".join(tldextract.extract(hostname)[1:]) in domains
            ]
            used_in_dns_record = any(
                address in [k.address for k in check_ip(hostname)]
                for hostname in whitelist_tld
            )

            if not used_in_dns_record:
                print("\t= {} : {}".format(address, hostnames[0]))
            else:
                print("\t+++ {} : {}".format(address, "|".join(hostnames)))
                break

        print("\t- {:15}".format(address), end="\r")

        for _ in range(3):
            try:
                engine.release_address(AllocationId=allocation_id)
                break
            except Exception:
                time.sleep(1)
                print("Release exception")

    print("\n")


if __name__ == "__main__":
    print(Description)

    parser = argparse.ArgumentParser(
        description=Description, formatter_class=argparse.RawDescriptionHelpFormatter
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
    ip_list = filter_ips_by_region(args.region)

    procs = []
    for _ in range(args.processes):
        proc = Process(target=main, args=(args,))
        procs.append(proc)
        proc.start()
        time.sleep(1)

    for proc in procs:
        proc.join()
