import time
import re
import sys
import argparse
import requests
import random
import string
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from pprint import pprint
from multiprocessing import Process

Description = """                      
 _____ _           _ _____                     
|     | |___ _ _ _| | __  |___ ___ ___ ___ ___ 
|   --| | . | | | . |    -| .'|  _| . | . |   |
|_____|_|___|___|___|__|__|__,|___|___|___|_|_|
    Cloud IP Hunting - Proof of Concept [GCP]         
"""
SearchRegions = ["us-east1", "us-central1", "us-west1", "us-west2", "us-east4"]
Session = None
CSRFToken = None


def get_hostnames(address):
    global Session
    global CSRFToken
    if not Session:
        # print('[+] Opening session for Security Trails ...')
        Session = requests.Session()
        response = Session.get("https://securitytrails.com/list/ip/1.1.1.1")
        CSRFToken = re.findall(r'csrf_token = "(\S+?)"', response.text)[0]
    response = Session.post(
        f"https://securitytrails.com/app/api/v1/list?ipv4={address}",
        json={"_csrf_token": CSRFToken},
    )
    if response.status_code != 200:
        print("[!] SecurityTrails request failed!")
        print(response.text)
        sys.exit(1)
    records = response.json().pop("records", [])
    if records:
        return [r["hostname"] for r in records]
    return []


def start_loop(project_name, number_of_loops, region_name):
    driver = get_driver(Provider.GCE)
    engine = driver("", "", project=project_name)

    print("[+] Connected to GCP.\n")
    previously_seen = []
    for l in range(number_of_loops):
        print("[+] (L{}) Allocating {} new address".format(l, 1))

        name = "".join(random.choice(string.ascii_lowercase) for _ in range(0, 8))

        ip = engine.ex_create_address(name, region_name)

        if ip.address in previously_seen:
            print("\t- {} is duplicate".format(ip.address))
            ip.destroy()
            continue

        previously_seen.append(ip.address)
        records = get_hostnames(ip.address)

        if not records or all(
            True if "googleusercontent.com" in record else False for record in records
        ):
            print("\t- {}".format(ip.address))
            ip.destroy()
            continue

        print("\t++ {}\n".format(ip.address))
        pprint(records)
        break
    print("\n[+] Done.")


def main(arguments):
    parser = argparse.ArgumentParser(
        description=Description, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("project", help="GCP project to hold assets under")
    parser.add_argument("-l", "--loops", help="Number of loops", default=300)
    parser.add_argument(
        "-r",
        "--region",
        help="Region to search",
        default="us-east1,us-central1,us-west1,us-west2,us-east4",
    )
    args = parser.parse_args(arguments)

    print(Description)

    procs = []
    for _ in range(8):
        proc = Process(target=start_loop, args=(args.project, args.loops, args.region))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
