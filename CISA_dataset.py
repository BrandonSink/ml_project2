# Import libraries
import pandas as pd
import requests,json,time
from datetime import datetime

# Import API creds file
import creds

# Read in the the latest "Known Exploited Vulnerabilities Catalog" CSV from CISA
url='https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
cisa = pd.read_csv(url)

# Create dataframe with desired fields, and empty lists.
df = cisa[['cveID','dateAdded','vendorProject','product']]
pub_list = []
cvss2_list = []
cvss31_list = []

# Get additional data for each CVE using API
# API Key must be requested from NIST (https://nvd.nist.gov/developers/api-key-requested)
for i in df['cveID']:
    headers = {'apiKey':creds.api_key}
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='

    response = requests.get(url + i, headers=headers)
    data = response.json()

    # Get available data, if it is not available return None.
    try:
        published = (data['vulnerabilities'][0]['cve']['published'])
        pub_list.append(published)
    except:
        pub_list.append(None)
        
    try: 
        cvss2 = None 
        cvss2 = (data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'])
        cvss2_list.append(cvss2)
    except:
        cvss2_list.append(None)
        
    try:
        cvss31 = None
        cvss31 = (data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])
        cvss31_list.append(cvss31)
    except:
        cvss31_list.append(None)
    
    print(f'{i}')

    # Rate limiting. API only allows 50 requests per 30 seconds with key.
    time.sleep(1)

# Add columns to dataframe
pd.options.mode.chained_assignment = None
df['datePublished'] = pub_list
df['CVSS v2'] = cvss2_list
df['CVSS v3.1'] = cvss31_list

# Remove time from datePublished
df['datePublished'] = df['datePublished'].str.split('T').str[0]

# Convert dates to datetime format and calculate the difference
df['datePublished'] = pd.to_datetime(df['datePublished'])
df['dateAdded'] = pd.to_datetime(df['dateAdded'])

df['days'] = df['dateAdded'] - df['datePublished']
df['days'] = df['days'].dt.days

# Output to CSV
df.to_csv('dataset.csv')