"""
This script adds IPs from Recorded Future and Salt Security to the
appropriate lists in Cloudflare, which are then used to block malicious
traffic in the WAF.
"""
import os
import time

import CloudFlare
from dotenv import load_dotenv

load_dotenv()

AID = os.getenv("AID")
MAL_LID = os.getenv("MAL_LID")
SALT_LID = os.getenv("SALT_LID")
API_KEY = os.getenv("API_KEY")
EMAIL = os.getenv("EMAIL")
TIMEOUT = 10


def add_rf_ip():
    """
    This function adds the IPs from the Recorded Future IP risk list
    to the malicious_ip_list in Cloudflare.
    """
    cf = CloudFlare.CloudFlare(email=EMAIL, token=KEY)
    with open("malicious_ips.csv", "r", encoding="utf-8") as i_file:
        for line in i_file:
            if line.startswith("ip"):
                continue
            new_ip = line.strip()
            new_rule = cf.accounts.rules.lists.items.post(
                AID,
                MAL_LID,
                data=[
                    {
                        "ip": new_ip,
                        "comment": "Malicious IP sourced from Recorded Future",
                    }
                ],
            )
            print(f"New entry: {new_rule}\n")
            time.sleep(1)


def add_salt_ip():
    """
    This function adds threat actor IPs from the Salt API Security platform
    to the salt_attackers list in Cloudflare.
    """
    cf = CloudFlare.CloudFlare(email=EMAIL, token=KEY)
    with open("salt_ips.csv", "r", encoding="utf-8") as i_file:
        for line in i_file:
            new_ip = line.strip()
            new_rule = cf.accounts.rules.lists.items.post(
                AID,
                SALT_LID,
                data=[
                    {
                        "ip": new_ip,
                        "comment": "Malicious IP sourced from Attacker IP in Salt Security",
                    }
                ],
            )
            print(f"New entry: {new_rule}\n")
            time.sleep(1)


def main():
    add_rf_ip()
    add_salt_ip()


if __name__ == "__main__":
    main()
