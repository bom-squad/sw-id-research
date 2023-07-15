import nvdlib
import pandas as pd
import cache

# Get set of CVES for a set of cpes
def get_cpe_set_cves(cpe_list):
    cpe_cves_cache = cache.FileCache('cpe_cves_cache1.json')
    cve_set = set()
    cve_intersection = set()
    first_cpe = True
    for cpe in cpe_list:
        cpe_cves = cpe_cves_cache.get(cpe)
        if cpe_cves is None or len(cpe_cves) == 0:
            # Try to get the CVEs for the CPE
            print(f'Getting CVEs for {cpe}')
            cpe_cves = set()
            try:
                r = nvdlib.searchCVE(keywordSearch=cpe, key="12c1601d-928b-440d-820c-bb306860c807")
            except:
                cpe_cves_cache.add(cpe, [])
                cpe_cves_cache.flush()
                print(f'Error getting CVEs for {cpe}')
                continue
            for cve in r:
                cpe_cves.add(cve.id)
            # add to the cache
            cpe_cves_cache.add(cpe, list(cpe_cves))
            cpe_cves_cache.flush()

        else:
            cpe_cves = set(cpe_cves)
            print(f'Got CVEs for {cpe} from cache')

        # Accumulate results:
        cve_set = cve_set | cpe_cves
        
        if first_cpe:
            cve_intersection = cpe_cves
            first_cpe = False
        else:
            print(f'acc. inters {len(cve_intersection)}, cpe_cves {len(cpe_cves)}')
            cve_intersection = cve_intersection & cpe_cves

    # convert set to list
    return set(sorted(cve_set)), set(sorted(cve_intersection))


# Get a set of CVES for a purl
def get_purl_cpes(purl):
    cpe_set = set()
    df = pd.read_csv('purl2cpe-mapping.csv')
    df = df[df['purl'] == purl]
    for index, row in df.iterrows():
        cpe_set.add(row['cpe'])
    return set(sorted(cpe_set))

def get_purl_cves(purl):
    cve_set = set()
    df = pd.read_csv('purl2cpe-mapping.csv')
    df = df[df['purl'] == purl]
    for index, row in df.iterrows():
        cve_set.add(row['cve'])
    return set(sorted(cve_set))



def cpe_cve_inetrsection_experiment():
    results = cache.FileCache('MultipleCPEresults.json')
#    purl = "pkg:pypi/cryptography"
#    purl = 'pkg:pypi/ansible'
    purl = 'pkg:pypi/django'
    purl_cves = get_purl_cves(purl)
    purl_cpes = get_purl_cpes(purl)
    cpe_cves, cpe_cves_intersection = get_cpe_set_cves(purl_cpes)
    
    results.add(purl, list(purl_cves))
    results.add(f'{purl}-cpes', list(purl_cpes))
    results.add(f'{purl}-cpe-cves', list(cpe_cves))
    results.add(f'{purl}-cpe-cves-intersection', list(cpe_cves_intersection))
    results.add(f"{purl}-purl-cves_-_cpe cves", list(purl_cves - cpe_cves))
    results.add(f"{purl}-purl-cves_-_cpe cves intersection", list(purl_cves - cpe_cves_intersection))
    results.add(f"{purl}-cpe-cves_-_purl cves", list(cpe_cves - purl_cves))
    results.add(f"{purl}-cpe-cves-intersection_-_purl cves", list(cpe_cves_intersection - purl_cves))
    results.flush()
    

def get_purl_and_cve_cpes(purl,cve):
    cpe_set = set()
    df = pd.read_csv('purl2cpe-mapping.csv')
    df = df[df['purl'] == purl]
    df = df[df['cve'] == cve]

    for index, row in df.iterrows():
        cpe_set.add(row['cpe'])
    return set(sorted(cpe_set))    

def check_cpe_cve(cve, cpe_list):
    cpe_cves_cache = cache.FileCache('cpe_cves_cache.json')
    for cpe in cpe_list:
        cpe_cves = cpe_cves_cache.get(cpe)
        if cpe_cves is None or len(cpe_cves) == 0:
            # Try to get the CVEs for the CPE
            print(f'Getting CVEs for {cpe}')
            cpe_cves = set()
            try:
                r = nvdlib.searchCVE(cpeName=cpe, key="12c1601d-928b-440d-820c-bb306860c807")
            except:
                cpe_cves_cache.add(cpe, [])
                cpe_cves_cache.flush()
                print(f'Error getting CVEs for {cpe}')
                continue
            for c in r:
                cpe_cves.add(c.id)
            # add to the cache
            cpe_cves_cache.add(cpe, list(cpe_cves))
            cpe_cves_cache.flush()

        else:
            cpe_cves = set(cpe_cves)
            print(f'Got CVEs for {cpe} from cache')

        if cve not in cpe_cves:
            print(f'cve {cve} not in cpe_cves for {cpe}')

def signle_cve_experiment():
    """
    Verify thet all cpes of a single cve to indeed point to this cve (when searching by cpe)
    """
    purl = 'pkg:pypi/django'
    purl_cves = get_purl_cves(purl)
    for cve in purl_cves:
        purl_cpes = get_purl_and_cve_cpes(purl,cve)
        check_cpe_cve(cve, purl_cpes)


def vesioned_purl_experiment():
    purl = "pkg:pypi/cryptography"
    version = "39.0.0"
    cvel = ["CVE-2023-23931", "CVE-2023-0286"]
    # create cpe list from the nvdJosv
    nvdJosv_cpes = set()
    for cve in cvel:
        nvdJosv_cpes = nvdJosv_cpes | get_purl_and_cve_cpes(purl, cve)
    
    # Assume nvdJosv_cpes is the identifier.
    # Check which vulnerabilities this cpes list generates

    # for cpe:2.3:a:cryptography_project:cryptography:*:*:*:*:*:python:*:*
    # CVE-2023-23931,CVE-2020-36242

    # for cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*
    # These two vulnerabilities do not include this cpe.
    # The 0286 is due to cpe-openssl, not cpe-cryptography

    cpe_cves, cpe_cves_intersection = get_cpe_set_cves(nvdJosv_cpes)
    
    print(f'cpe_cves_intersection: {cpe_cves_intersection}')
    print(f'cpe_cves: {cpe_cves}')
    
if __name__ == '__main__':
    # signle_cve_experiment()
    vesioned_purl_experiment()



    # The experiment:
    # Check if the cpe list of cpes we associated with a purl using the osv-nvd join can serve as an identifier.
    # We expect that the intersect of the vulnerabilities of the list of cpes will produce the same set of 
    # cves as we got from the purl.

    # Results:
    # The interesect is an empty set - this is strange.

    # Next step: try for specifc prul and cve - check if all cpes have this vunerability
    # Results: all cpes have the vulnerability, done for all (djandgo, django-cve) pair

    # Next step: try for a specific version.
    # for that we need to the the list of versions, list of CVEs relevant to these versions and the list of cpes.
    # a good choice for that is pkg:pypi/cryptography which has the following CVES:
        # "CVE-2020-25659",
        # "CVE-2023-0286",
        # "CVE-2020-36242",
        # "CVE-2018-10903",
        # "CVE-2016-9243",
        # "CVE-2023-23931"

    