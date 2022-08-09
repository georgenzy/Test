#!/usr/bin/env python
# coding: utf-8
import urllib.request
import re
import whois
import pandas as pd
from bs4 import BeautifulSoup
import socket


# ### 1. Provide a script to automate the extraction of IP addresses, URLs and hashes from the following cyber threat report.
# 
# ### “Hiding in plain sight: PhantomLance walks into a market”
# ### (https://securelist.com/apt-phantomlance/96772)
# ### You can use any open source tools and library to help with the extraction.

# Read URL
link = "https://securelist.com/apt-phantomlance/96772/"
webpage = urllib.request.urlopen(link).read().decode('UTF-8')

# Get text after h3 tag with id = md5
webpage_After_MD5 = webpage.split("<h3 id=\"md5\">MD5</h3>",1)[1]
soup = BeautifulSoup(webpage_After_MD5, "html.parser")

IP = []
hashes = []
websites = []

for h4_tag in soup.find_all('h4'):
    
    # Get text in tags after h4 tags
    current_text = h4_tag.next_sibling.next_sibling.text
    
    # Replace [.] with . for URLs
    current_text = current_text.replace("[.]", ".")
    
    # Split by line break
    current_list = current_text.split("\n")
    
    for element in current_list:
        # Check if element is an IP address
        try:
            socket.inet_aton(element)
            IP.append(element)
        except:
            pass
        
        try:
            socket.inet_pton(socket.AF_INET6, element)
            IP.append(element)
        except:
            pass
        
        # Check if element is a hash else it is a URL
        if re.search('[0-9a-fA-F]{32}', element):
            hashes.append(element)
        else:
            websites.append(element)


# ### 2. With the domains extracted, develop a python script to extract WHOIS information for each domain. The output should be in a CSV file. You can use any open source library to develop the python script.

# Get whois information for each URL and concatenate into output dataframe
valid_found = False

for url in websites:
    try:
        whois_information = whois.whois(url)
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

# Output to CSV
whois_data[whois_data['domain_name'].notna()].to_csv("Part A Q2.csv", index=False)






