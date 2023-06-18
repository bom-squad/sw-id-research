import os
import pandas as pd
import sqlite3
import json
import requests
from dotenv import dotenv_values

# %%
# upload the CPE dictionary to a sqlite database

def upload_cves(cve_list):
    # if cve_list empty, read it from file:
    if cve_list == None:
        # read list from cve_list.txt
        with open('cve_list.txt', 'r') as f:
            cve_list = [line.rstrip('\n') for line in f]
    l = len(cve_list)
    # Load the environment variables from .env into a dictionary
    env_vars = dotenv_values()

    # Access the values using the keys
    nvd_key = env_vars['NVD_API']
    # Create dataframe for vulneability, cpe, cpe-match-criteria, references
    cve = pd.DataFrame(columns=['cve', 'cpe'])

    cve_json = None
    # loop through all cve entries
    for cve_id in cve_list:
        print("CVE:{} #{}".format(cve_id,l))
        l -= 1
        # check if cve already exists as file
        if os.path.isfile('cve/{}.json'.format(cve_id)):
            # read cve from file
            with open('cve/{}.json'.format(cve_id)) as json_file:
                cve_json = json.load(json_file)
        else:
            # get cve data from nvd

            # https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}".format(cve_id)
            response = requests.get(url, auth=(nvd_key, ''))
            cve_json = response.json()
            # save json as file with cve_id as name
            with open('cve/{}.json'.format(cve_id), 'w') as outfile:
                json.dump(cve_json, outfile)

        if cve_json is None:
            print("cve_json is None")
            continue

        if 'vulnerabilities' not in cve_json:
            print(cve_json)
            continue
        cve_json = cve_json['vulnerabilities']
        if len(cve_json) == 0:
            print("No vulnerabilities data in json for {}".format(cve_json))
            continue
        cve_json = cve_json[0]
        if 'cve' not in cve_json:
            print(cve_json)
            continue
        cve_json = cve_json['cve']
        
        # get the cpe data from the cve
        if "configurations" in cve_json:
            cpes = [
                m["criteria"] for conf in cve_json["configurations"] for node in conf["nodes"] for m in node["cpeMatch"]
            ]
        # add all cpe entries to the cve dataframe
            for cpe in cpes:
                cve = cve.append({'cve': cve_id, 'cpe': cpe}, ignore_index=True)
        else:
            continue
    #    time.sleep(2)
    cve.to_csv('cve.csv', sep=',', header=True, index=False)

upload_cves(None)