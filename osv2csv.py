import os
import pandas as pd
import json

# %%
# upload parts of osv-files to sqlite database
# in this demo the folder 'osv' contains only python vulnerability files
def upload_osv_files():
    # create a connection to the database
    #conn = postgres_engine("") #sqlite3.connect('cpe-oss.db')
    # get all files in the folder
    files = os.listdir('osv')
    cve_list = []
    # create an osv data frame with the following columns:
    # ghsa, cve, ecosystem, packageName, version, purl, reference
    #osv = pd.DataFrame(columns=['ghsa', 'cve', 'ecosystem', 'packageName', 'version', 'purl', 'reference'])
    reference = pd.DataFrame(columns=['id', 'cve', 'ecosystem', 'packageName', 'version', 'purl', 'reference'])
    # loop through all files
    for file in files:
        # load the file to a json object named osv_json
        with open('osv/' + file) as f:
            osv_json = json.load(f)

        # get the ghsa
        id = osv_json['id']
        # get the cve
        # TODO: search cve entry in the aliases list
        if 'aliases' in osv_json:
            cve = osv_json['aliases'][0]
            if cve.startswith('CVE'):
                cve_list.append(cve)
            else:
                cve = None
        else:
            cve = None
        # get the ecosystem
        # TODO: get the ecosystem from the osv objec
        ecosystem = "pypi"
        # check if the affected object is not empty
        if 'affected' in osv_json:
        # get the package name and version
            packageName = osv_json['affected'][0]['package']['name']
            version = None # TODO: Decide what to put here
            purl = osv_json['affected'][0]['package']['purl']
        else:
            packageName = None
            version = None
            purl = None
        
        # create a data frame with a row for each referecne
        # the data frame has the following columns:
        # ghsa, cve, ecosystem, packageName, version, purl, reference
        # the reference is a url to the vulnerability
        
        # loop through all references
        for ref in osv_json['references']:
            # get the url
            url = ref['url']
            # append the reference to the data frame
            reference = reference.append({'id': id, 'cve': cve, 'ecosystem': ecosystem, 'packageName': packageName, 'version': version, 'purl': purl, 'reference': url}, ignore_index=True)  
        
    # upload the dataframe to the database, to the table osv
    #reference.to_sql('osv', conn, if_exists='replace', schema='osint',index=False)
    reference.to_csv('osv.csv', sep=',', header=True, index=False)
    # close the connection
    #conn.close()
    #save list to file
    with open('cve_list.txt', 'w') as f:
        for item in cve_list:
            f.write("%s\n" % item)

    return cve_list

upload_osv_files()