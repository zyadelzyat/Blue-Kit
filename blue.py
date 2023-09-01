#!/usr/bin/env python3 

# this steps for making your script run in any place in the system 
"""
chmod +x blue.py
pwd "then take the path of where the script downloaded"
nano ~/.bashrc
export PATH="/path/to/your/script:$PATH"
source ~/.bashrc    

"""
import psutil
import subprocess
import csv
import hashlib
import click
import json
import pandas
import pandas as pd
import matplotlib.pyplot as plt
import os
import requests
from rich.console import Console
import shodan
import re
import base64
import keyboard
import readline  
import zipfile
import pyzipper
import binascii
import subprocess 

ABUSEIPDB_API_KEY = '1c786000241b0f26aafef1c2182b4386d907d90ee996ab64d50a6ae344f4c0b8db9bceddf5a2bc7e'
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
VIRUSTOTAL_API_KEY = "b99a826416c1b557e9b6351ade46b80c92b5672c7bae9f5e1eb6bbc70758dddf"
SHODAN_API_KEY = "JZqLIVkhBe1qCelESNg79Zv3z0d1FG4C"
MALWARE_BAZAAR_API_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"

def print_banner():
    # Function to print the tool banner
    console = Console()
    console.print(r"""
 ____  _            _  ___ _   
| __ )| |_   _  ___| |/ (_) |_ 
|  _ \| | | | |/ _ \ ' /| | __|
| |_) | | |_| |  __/ . \| | |_ 
|____/|_|\__,_|\___|_|\_\_|\__|

             _____________
           /     __      /|
          /   __/ /_    / /
         /   /_  __/   / //
        /     /_/     / //
       /_____________/ //
       |______&______|//
       |_____________|


[*] Combination Of Tools For Daily Tasks Malware Analysts , SOC Analysts , Threat Hunters 
[*] This Tool Created By Zyad Elzyat   

    """, style="bold cyan")
    


def clear_terminal():
    # Function to clear the terminal screen
    os.system("clear" if os.name == "posix" else "cls")
    
csv_columns = ['ipAddress', 'isPublic', 'ipVersion', 'isWhitelisted', 'abuseConfidenceScore',
               'countryCode', 'usageType', 'isp', 'domain', 'hostnames', 'totalReports',
               'numDistinctUsers', 'lastReportedAt', 'isTor']

def read_ip_addresses_from_csv(csv_file):
    try:
        df = pd.read_csv(csv_file)
        ip_addresses = df['IP'].tolist()
        return ip_addresses
    except Exception as e:
        print("Error reading CSV file:", str(e))
        return []
    
def abuseipdb_check(ip_addresses, output_csv, output_json):
    results = []
    try:
        csv_columns = ['ipAddress', 'isPublic', 'ipVersion', 'isWhitelisted', 'abuseConfidenceScore',
                       'countryCode', 'usageType', 'isp', 'domain', 'hostnames', 'totalReports',
                       'numDistinctUsers', 'lastReportedAt', 'isTor']

        for ip_address in ip_addresses:
            parameters = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': ABUSEIPDB_API_KEY
            }

            response = requests.get(url=ABUSEIPDB_URL, headers=headers, params=parameters)
            json_data = json.loads(response.content)
            json_main = json_data["data"]
            results.append(json_main)

        # Save results in CSV
        with open(output_csv, "w", newline='') as filecsv:
            writer = csv.DictWriter(filecsv, fieldnames=csv_columns)
            writer.writeheader()
            for result in results:
                writer.writerow(result)

        # Save results in JSON
        with open(output_json, "w") as json_file:
            json.dump(results, json_file, indent=4)

        print(f"AbuseIPDB check completed for {len(ip_addresses)} IP addresses. Results saved to {output_csv} and {output_json}")
    except Exception as e:
        print("An error occurred:", str(e))
def query_virustotal(resource):
    # Function to query VirusTotal API and return the response
    url = f"https://www.virustotal.com/api/v3/files/{resource}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()
    

def query_shodan(ip_address):
    # Function to query Shodan API and return the response
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        result = api.host(ip_address)
        return result
    except shodan.APIError as e:
        print("Shodan Error:", e)
        return None
    


def check_and_decode_base64_in_file(file_path, output_file):
    with open(file_path, 'rb') as file:
        content = file.read()

        try:
            decoded_content = base64.b64decode(content)
            decoded_text = decoded_content.decode('utf-8')  # Assuming the content is text

            with open(output_file, 'w') as output_file:
                output_file.write(decoded_text)
            
            return "Base64 content decoded and saved correctly"
        except base64.binascii.Error:
            return "No Base64 encoded content found in the file."
        

def download_sample(sha256_hash):
    url = MALWARE_BAZAAR_API_ENDPOINT
    data = {
        "query": "get_file",
        "sha256_hash": sha256_hash
    }
    
    response = requests.post(url, data=data)
    if response.status_code == 200:
        file_content = response.content
        file_name = f"{sha256_hash}.zip"
        
        with open(file_name, "wb") as f:
            f.write(file_content)
        
        print(f"Sample downloaded and saved as {file_name}")
    else:
        print("Sample download failed")
    
    
def save_output(filename, data, output_format="json"):
    # Function to save the output in CSV, JSON, or PNG format
    if output_format == "json":
        with open(filename + ".json", "w") as f:
            json.dump(data, f, indent=4)
        print("JSON Output saved to", filename + ".json")

    elif output_format == "csv":
        if "data" in data and "attributes" in data["data"]:
            attributes = data["data"]["attributes"]
            if "last_analysis_stats" in attributes:
                stats = attributes["last_analysis_stats"]
                if "malicious" in stats and "undetected" in stats:
                    total_scans = stats["malicious"] + stats["undetected"]
                else:
                    total_scans = 0
            else:
                total_scans = 0
        else:
            total_scans = 0

        if "data" in data and "attributes" in data["data"]:
            attributes = data["data"]["attributes"]
            if "last_analysis_results" in attributes:
                results = attributes["last_analysis_results"]
            else:
                results = {}
        else:
            results = {}

        df = pd.DataFrame(results).T
        df["Malicious"] = df["category"].apply(lambda x: 1 if x == "malicious" else 0)
        df.to_csv(filename + ".csv", index=False)
        print(f"CSV Output saved to {filename}.csv. Total Scans: {total_scans}, Malicious: {df['Malicious'].sum()}")
        return df
    
def hex_editor(file_path):
    try:
        output_file = file_path + "_hex_dump.txt"
        hex_command = f"hexdump -C {file_path} > {output_file}"
        
        subprocess.run(["bash", "-c", hex_command])
        
        print(f"Hex dump saved to {output_file}")
    except FileNotFoundError:
        print("File not found")
        
def extract_strings_from_file(file_path):
    try:
        output_file = file_path + "_strings.txt"
        strings_command = f"strings {file_path} > {output_file}"
        
        subprocess.run(["bash", "-c", strings_command])
        
        print(f"Strings extracted and saved to {output_file}")
    except FileNotFoundError:
        print("File not found")

def calculate_file_hashes(file_path):
    try:
        with open(file_path, "rb") as file:
            content = file.read()
            hash_md5 = hashlib.md5(content).hexdigest()
            hash_sha1 = hashlib.sha1(content).hexdigest()
            hash_sha256 = hashlib.sha256(content).hexdigest()

        return hash_md5, hash_sha1, hash_sha256

    except FileNotFoundError:
        print("File not found")

def save_hashes_to_file(file_path, hashes):
    with open(file_path, "w") as file:
        file.write("MD5 Hash: " + hashes[0] + "\n")
        file.write("SHA-1 Hash: " + hashes[1] + "\n")
        file.write("SHA-256 Hash: " + hashes[2] + "\n")
        
        
def print_options():
    print("Choose an option:")
    print("-----------------")
    print("[1]. Perform VirusTotal Query")
    print("[2]. Perform Shodan Query")
    print("[3]. AbuseAbuseIPDB")
    print("[4]. Calculate File Hash")
    print("[5]. Extract Strings from File")
    print("[6]. Decode Base64")
    print("[7]. Check Magic Number Using Hex Editor")
    print("[8]. MalwareBazzar Password IS >> infected")
    print("[0]. Exit")
    


def cli():
    clear_terminal()
    print_banner()

    while True:
        print_options()
        choice = input("Enter your choice: ")

        if choice == '0':
            break

        if choice == '1':
            query = input("Enter Hash or IP or Domain or URL: ")
            result_virustotal = query_virustotal(query)
            if "error" in result_virustotal:
                print("VirusTotal Error:", result_virustotal["error"]["message"])
            else:
                save_output("virustotal_output", result_virustotal, "csv")
                save_output("virustotal_output", result_virustotal, "json")

        elif choice == '2':
            query = input("Enter IP: ")
            result_shodan = query_shodan(query)
            if result_shodan is not None:
                save_output("shodan_output", result_shodan, "json")
                
        elif choice == '3':
            input_type = input("Enter '1' to enter IP addresses manually or '2' to provide a CSV file: ")
            if input_type == '1':
                ip_addresses = input("Enter a comma-separated list of IP addresses to scan or one IP: ").split(',')
            elif input_type == '2':
                csv_file = input("Enter the path to the CSV file containing IP addresses: ")
                ip_addresses = read_ip_addresses_from_csv(csv_file)
            else:
                print("Invalid input type.")
                continue

            output_csv = input("Enter the output CSV file name: ")
            output_json = input("Enter the output JSON file name: ")
            abuseipdb_check(ip_addresses, output_csv, output_json)
            
        elif choice == '4':
            file_path = input("Enter the path to the file you want to calculate hashes for: ")
            file_path = file_path.strip()
            hashes = calculate_file_hashes(file_path)

            print("MD5 Hash:", hashes[0])
            print("SHA-1 Hash:", hashes[1])
            print("SHA-256 Hash:", hashes[2])

            save_hashes = input("Do you want to save the hashes to a file? (y/n): ")
            if save_hashes.lower() == 'y':
                output_file = input("Enter the name of the output file: ")
                save_hashes_to_file(output_file, hashes)
                print("Hashes saved to", output_file) 
        
        elif choice == '5':
            file_path = input("Enter the path to the file you want to extract strings from: ")
            file_path = file_path.strip()
            extract_strings_from_file(file_path)

        
                     
        elif choice == '6':
            file_path = input("Enter the path to the file you want to check: ")
            file_path = file_path.strip()

            output_file = input("Enter the output file name to save the decoded content: ")
            decoded_result = check_and_decode_base64_in_file(file_path, output_file)
            print(decoded_result)

     
        elif choice == '7':
            file_path = input("Enter the path to the file you want to edit in hex: ")
            file_path = file_path.strip()
            hex_editor(file_path)
                 

        elif choice == '8':
            sha256_hash = input("Enter the SHA-256 hash of the sample: ")
            download_sample(sha256_hash)

            
        elif choice == '-':
            continue  # This will continue to the next iteration of the loop
        else:
            print("Invalid choice. Please choose a valid option.")


if __name__ == "__main__":
    cli()