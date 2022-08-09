#!/usr/bin/env python
# coding: utf-8

# In[24]:


import pandas as pd
import re
import whois
from pysafebrowsing import SafeBrowsing


# In[21]:


# Assumptions:
# 1. All IP addresses are not private and whois data can be retrieved.
# 2. "Russia" is a hotspot for malware activities
# 3. Assume API key is valid for Google's safe browsing API


# In[22]:


# For reference only: columns = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "trans_depth", "method", "host", "uri", "referrer", "user_agent", "request_body_len", "response_body_len", "status_code", "status_msg", "info_code", "info_msg", "filename", "tags", "username", "password", "proxied", "orig_fuids", "orig_mime_types", "resp_fuids", "resp_mime_types"])


# In[2]:


# Reading file
file = open('http.log', 'r')
lines = file.read().splitlines()
file.close()


# In[16]:


# Create list of IPs to search
IPs = []


# In[17]:


# Get Originating IPs for analysis
for line in lines:
    IPs.append(line.split("\t")[2])


# In[18]:


# Get unique IPs
IPs = list(set(IPs))


# In[19]:


# Clean IPs - Remove those with colons
regex = re.compile(r'^\w+:\w+')
filtered_IPs = [i for i in IPs if not regex.match(i)]


# In[20]:


# Get whois information for each URL and concatenate into output dataframe
valid_found = False

for IP in filtered_IPs:
    try:
        whois_information = whois.whois(IP)
        
        # Create dataframe with whois object attributes as column names
        if valid_found == False:
            whois_data = pd.DataFrame(columns = list(whois_information.keys()))
            valid_found = True
    
        # Change to dataframe
        whois_information_df = pd.DataFrame(whois_information.items()).T

        # Rename header for merging
        new_header = whois_information_df.iloc[0] # First row as header
        whois_information_df = whois_information_df[1:] # Remove header row
        whois_information_df.columns = new_header # Set header row as header

        whois_data = pd.concat([whois_data, whois_information_df], ignore_index=True)
        
    except:
        pass


# In[22]:


# Retrieving rows originating from "Russia"
hotspot_IP_country = whois_data[whois_data['country'] == "Russia"]


# In[ ]:


# Retrieving domains that are malicious based on Google's safe browsing API (This will not work as there is no API key and no domain name)
found_malicious = False

s = SafeBrowsing("KEY")

for i in whois_data.shape[0]:
    
    result = s.lookup_urls(whois_data.iloc[[i]]['domain_name'])
    
    if result[whois_data.iloc[[i]]['domain_name']]['malicious'] == True:
        # Create dataframe with whois object attributes as column names
        if found_malicious == False:
            malicious_domains = whois_data.iloc[[i]]
            found_malicious = True
        else:
            malicious_domains = pd.concat([malicious_domains, whois_data.iloc[[i]]], ignore_index=True)
    except:
        pass


# In[ ]:


# Retrieve data that may be malicious
flagged_data = whois_data[whois_data['country'] == "Russia" | whois_data['domain_name'].isin(malicious_domains['domain_name'])]
flagged_data_index = list(flagged_data.index.values)
flagged_IP = [filtered_IPs[i] for i in flagged_data_index]

