"""
This script downloads the Recorded Future IP risk list and appends the entries to a dictionary,
which is then de-duplicated & saved as malicious_ips.csv. This new CSV is then used in the
update_ioc_list.py script to add the IPs to the appropriate IP list in Cloudflare.
"""
import csv
import os

import pandas as pd
import requests
import urllib3
import urllib3.exceptions
from dotenv import load_dotenv

import update_ioc_list as update

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

IP_URL = os.getenv("RF_IP_URL")
RF_KEY = os.getenv("RF_API")
HEADERS = {"X-RFToken": RF_KEY}
TIMEOUT = 10


def get_ip_iocs():
    """
    This function downloads the Recorded Future IP risk list and
    converts it to a CSV file.
    """
    response = requests.get(IP_URL, headers=HEADERS, verify=False, timeout=TIMEOUT)

    if response.status_code != 200:
        print("Failed to download IP list. Status code: ", response.status_code)
    else:
        reader = csv.reader(response.text.strip().split("\n"))
        ip = []
        for i, row in enumerate(reader):
            if i == 0:
                continue
            if row[0] != "":
                ip.append(row[0])
        ip_dict = {"ip": ip}
        dict_to_csv(ip_dict)
        remove_duplicates()


def dict_to_csv(ip_dict):
    """
    This function converts the dictionary of IPs to a CSV file.
    """
    df = pd.DataFrame(ip_dict)
    df.to_csv("risky_ips.csv", index=False)


def remove_duplicates():
    """
    This function removes duplicate IPs from the CSV file.
    The CSV file is then saved as malicious_ips.csv.
    """
    df = pd.read_csv("risky_ips.csv")
    duplicates = df.duplicated()
    no_duplicates = df[~duplicates]
    no_duplicates.to_csv("malicious_ips.csv", index=False)


def main():
    get_ip_iocs()
    dict_to_csv(get_ip_iocs())
    remove_duplicates()
    update.add_rf_ip()
    update.add_salt_ip()


if __name__ == "__main__":
    main()
