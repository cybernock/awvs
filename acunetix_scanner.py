#!/usr/bin/python
# -*- coding: UTF-8 -*-
import sys, os, time
import socket
import re
from time import strftime, gmtime

version = sys.version_info
if version < (3, 0):
    print('Python 3+ required')
    sys.exit()

import requests
import json, ast
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import configparser

scan_label = 'Script default label'
cf = configparser.ConfigParser()
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

print('Initializing~')
try:
    cf.read(r"config.ini", encoding='utf-8')
    secs = cf.sections()
    awvs_url = cf.get('awvs_url_key', 'awvs_url')
    apikey = cf.get('awvs_url_key', 'api_key')
    input_urls = cf.get('awvs_url_key', 'domain_file')
    excluded_paths = ast.literal_eval(cf.get('scan_seting', 'excluded_paths'))
    custom_headers = ast.literal_eval(cf.get('scan_seting', 'custom_headers'))
    limit_crawler_scope = cf.get('scan_seting', 'limit_crawler_scope').replace('\n', '').strip()
    scan_speed = cf.get('scan_seting', 'scan_speed').replace('\n', '').strip()
    scan_cookie = cf.get('scan_seting', 'cookie').replace('\n', '').strip()
    proxy_enabled = cf.get('scan_seting', 'proxy_enabled').replace('\n', '').strip()
    proxy_server = cf.get('scan_seting', 'proxy_server').replace('\n', '').strip()
    webhook_url = cf.get('scan_seting', 'webhook_url').replace('\n', '').strip()
    
    # New configuration options
    enable_api_discovery = cf.getboolean('scan_seting', 'enable_api_discovery', fallback=False)
    enable_web_socket = cf.getboolean('scan_seting', 'enable_web_socket', fallback=False)
    enable_jwt_scan = cf.getboolean('scan_seting', 'enable_jwt_scan', fallback=False)
    enable_graphql = cf.getboolean('scan_seting', 'enable_graphql', fallback=False)
    tech_detection = cf.getboolean('scan_seting', 'tech_detection', fallback=True)
    sensitive_data_scan = cf.getboolean('scan_seting', 'sensitive_data_scan', fallback=True)
    max_scan_duration = cf.getint('scan_seting', 'max_scan_duration', fallback=1440)  # minutes
    openapi_spec_file = cf.get('scan_seting', 'openapi_spec_file', fallback='')

except Exception as e:
    print('Initialization failed, failed to obtain config.ini, please check whether the configuration of the config.ini file is correct\n', e)
    sys.exit()

headers = {
    'Content-Type': 'application/json',
    "X-Auth": apikey,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot) Chrome/117.0.0.0 Safari/537.36"
}
add_count_suss = 0
error_count = 0
target_scan = False
target_list = []

def push_wechat_group(content):
    global webhook_url
    try:
        resp = requests.post(
            webhook_url,
            json={"msgtype": "markdown", "markdown": {"content": content}},
            timeout=10
        )
        if 'invalid webhook url' in str(resp.text):
            print('Enterprise WeChat key is invalid')
        elif resp.json().get("errcode", -1) != 0:
            print(f"Push failed: {resp.text}")
    except Exception as e:
        print(f"Push error: {str(e)}")

def get_scan_status():
    try:
        get_target_url = f"{awvs_url}/api/v1/me/stats"
        r = requests.get(get_target_url, headers=headers, timeout=30, verify=False)
        result = r.json()
        status_msg = f"Scanning: {result['scans_running_count']} | Waiting: {result['scans_waiting_count']} | "
        status_msg += f"Scanned: {result['scans_conducted_count']} | Vulnerabilities: {result['vuln_count']['total']}\n"
        
        if result['vuln_count']['critical'] > 0:
            status_msg += f"🚨 CRITICAL VULNS: {result['vuln_count']['critical']}\n"
        
        status_msg += "Top Vulnerabilities:\n"
        for vuln in result['top_vulnerabilities']:
            status_msg += f"- {vuln['name']}: {vuln['count']}\n"
            
        print(status_msg)
        return status_msg
    except Exception as e:
        print(f"Status error: {str(e)}")
        return ""

def get_status():
    try:
        r = requests.get(f"{awvs_url}/api/v1/targets", headers=headers, timeout=10, verify=False)
        if r.status_code == 401:
            print('AWVS authentication failed: Invalid API key')
            sys.exit()
        if r.status_code == 200 and 'targets' in r.text:
            print('Configuration valid')
            return True
    except Exception as e:
        print(f'AWVS connection failed: {str(e)}')
        sys.exit()
    return False

def get_target_list():
    print('Retrieving targets')
    target_list = []
    page = 0
    while True:
        try:
            url = f"{awvs_url}/api/v1/targets?c={page}&l=50"
            r = requests.get(url, headers=headers, timeout=30, verify=False)
            result = r.json()
            
            if not result.get('targets'):
                break
                
            for target in result['targets']:
                target_list.append({
                    'target_id': target['target_id'],
                    'address': target['address']
                })
                
            page += 50
        except Exception as e:
            print(f"Target list error: {str(e)}")
            break
            
    return target_list

def addTask(url, target):
    global scan_label
    try:
        url = f"{url}/api/v1/targets/add"
        data = {
            "targets": [{
                "address": target,
                "description": scan_label,
                "type": "default"
            }],
            "groups": []
        }
        r = requests.post(url, headers=headers, json=data, timeout=30, verify=False)
        result = r.json()
        return result['targets'][0]['target_id']
    except Exception as e:
        print(f"Add task error: {str(e)}")
        return None

def enable_modern_features(config_data):
    """Enable modern scanning features"""
    # API Discovery
    if enable_api_discovery:
        config_data["api_scanning"] = {"enabled": True}
    
    # Web Socket Scanning
    if enable_web_socket:
        config_data["websocket"] = {"enabled": True}
    
    # JWT Scanning
    if enable_jwt_scan:
        config_data["jwt_scanning"] = {"enabled": True}
    
    # GraphQL Support
    if enable_graphql:
        config_data["graphql"] = {"enabled": True}
    
    # Technology Detection
    config_data["tech_detection"] = {"enabled": tech_detection}
    
    # Sensitive Data Scanning
    config_data["sensitive_data"] = {"enabled": sensitive_data_scan}
    
    # Scan Duration Limit
    config_data["max_scan_duration"] = max_scan_duration
    
    return config_data

def add_openapi_spec(target_id):
    """Add OpenAPI specification for API scanning"""
    global openapi_spec_file
    if not openapi_spec_file or not os.path.exists(openapi_spec_file):
        return False
        
    try:
        url = f"{awvs_url}/api/v1/targets/{target_id}/configuration/openapi"
        with open(openapi_spec_file, 'rb') as f:
            files = {'file': f}
            r = requests.post(url, headers=headers, files=files, verify=False)
            
        if r.status_code == 200:
            print(f"OpenAPI spec added to target {target_id}")
            return True
        else:
            print(f"OpenAPI error: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"OpenAPI exception: {str(e)}")
    
    return False

def configuration(url, target_id, target, default_scanning_profile_id):
    global custom_headers, excluded_paths, limit_crawler_scope, scan_cookie, scan_speed
    global proxy_enabled, proxy_server
    
    configuration_url = f"{url}/api/v1/targets/{target_id}/configuration"
    
    # Base configuration
    config_data = {
        "scan_speed": scan_speed,
        "login": {"kind": "none"},
        "ssh_credentials": {"kind": "none"},
        "default_scanning_profile_id": default_scanning_profile_id,
        "sensor": False,
        "user_agent": headers['User-Agent'],
        "case_sensitive": "auto",
        "limit_crawler_scope": limit_crawler_scope == 'true',
        "excluded_paths": excluded_paths,
        "authentication": {"enabled": False},
        "proxy": {
            "enabled": proxy_enabled == 'true',
            "protocol": "http",
            "address": proxy_server.split(':')[0] if proxy_server else "",
            "port": int(proxy_server.split(':')[1]) if proxy_server and ':' in proxy_server else 8080
        },
        "technologies": [],
        "custom_headers": custom_headers,
        "custom_cookies": [{"url": target, "cookie": scan_cookie}] if scan_cookie else [],
        "debug": False,
        "client_certificate_password": "",
        "issue_tracker_id": "",
        "excluded_hours_id": ""
    }
    
    # Add modern features
    config_data = enable_modern_features(config_data)
    
    try:
        r = requests.patch(
            url=configuration_url,
            json=config_data,
            headers=headers,
            timeout=30,
            verify=False
        )
        if r.status_code != 204:
            print(f"Configuration error: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"Configuration exception: {str(e)}")

def scan(url, target, profile_id, is_to_scan):
    target_id = addTask(url, target)
    if not target_id:
        return [0, "Failed to add target"]
        
    try:
        # Configure target
        configuration(url, target_id, target, profile_id)
        
        # Add OpenAPI spec if enabled
        if enable_api_discovery:
            add_openapi_spec(target_id)
            
        # Start scan if requested
        if is_to_scan:
            scan_url = f"{url}/api/v1/scans"
            data = {
                "target_id": target_id,
                "profile_id": profile_id,
                "incremental": False,
                "schedule": {
                    "disable": False,
                    "start_date": None,
                    "time_sensitive": False
                }
            }
            response = requests.post(scan_url, json=data, headers=headers, timeout=30, verify=False)
            result = response.json()
            return [1, result['target_id']]
        else:
            print(f"{target} added successfully (no scan)")
            return [2, target_id]
            
    except Exception as e:
        return [0, str(e)]

def delete_task():
    print("Deleting all scan tasks...")
    page = 0
    while True:
        try:
            url = f"{awvs_url}/api/v1/scans?l=50&c={page}"
            r = requests.get(url, headers=headers, timeout=30, verify=False)
            result = r.json()
            
            if not result.get('scans'):
                print("All scan tasks deleted")
                return
                
            for scan_task in result['scans']:
                task_id = scan_task['scan_id']
                task_address = scan_task['target']['address']
                del_url = f"{awvs_url}/api/v1/scans/{task_id}"
                del_res = requests.delete(del_url, headers=headers, timeout=30, verify=False)
                if del_res.status_code == 204:
                    print(f"Deleted scan for {task_address}")
                else:
                    print(f"Failed to delete {task_address}: {del_res.status_code}")
                    
            page += 50
        except Exception as e:
            print(f"Delete error: {str(e)}")
            return

def delete_targets():
    print("Deleting all targets...")
    page = 0
    while True:
        try:
            url = f"{awvs_url}/api/v1/targets?l=50&c={page}"
            r = requests.get(url, headers=headers, timeout=30, verify=False)
            result = r.json()
            
            if not result.get('targets'):
                print("All targets deleted")
                return
                
            for target in result['targets']:
                target_id = target['target_id']
                target_address = target['address']
                del_url = f"{awvs_url}/api/v1/targets/{target_id}"
                del_res = requests.delete(del_url, headers=headers, timeout=30, verify=False)
                if del_res.status_code == 204:
                    print(f"Deleted target {target_address}")
                else:
                    print(f"Failed to delete {target_address}: {del_res.status_code}")
                    
            page += 50
        except Exception as e:
            print(f"Delete error: {str(e)}")
            return

def create_custom_profile(profile_name, checks):
    try:
        url = f"{awvs_url}/api/v1/scanning_profiles"
        data = {
            "name": profile_name,
            "custom": True,
            "checks": checks
        }
        response = requests.post(url, json=data, headers=headers, timeout=30, verify=False)
        return response.json().get('profile_id')
    except Exception as e:
        print(f"Profile creation error: {str(e)}")
        return None

def get_profile_id(profile_name):
    try:
        url = f"{awvs_url}/api/v1/scanning_profiles"
        r = requests.get(url, headers=headers, timeout=30, verify=False)
        profiles = r.json().get('scanning_profiles', [])
        for profile in profiles:
            if profile['name'].lower() == profile_name.lower():
                return profile['profile_id']
    except Exception as e:
        print(f"Profile error: {str(e)}")
    return None

def monitor_critical_vulns():
    print("Starting critical vulnerability monitoring...")
    last_notified = {}
    
    while True:
        try:
            url = f"{awvs_url}/api/v1/vulnerabilities?severity=critical"
            r = requests.get(url, headers=headers, timeout=30, verify=False)
            vulns = r.json().get('vulnerabilities', [])
            
            current_time = time.time()
            for vuln in vulns:
                vuln_id = vuln['vuln_id']
                last_notify_time = last_notified.get(vuln_id, 0)
                
                # Notify only once per hour per vulnerability
                if current_time - last_notify_time > 3600:
                    msg = f"🚨 CRITICAL VULNERABILITY DETECTED!\n"
                    msg += f"Target: {vuln['target']['address']}\n"
                    msg += f"Vulnerability: {vuln['vt_name']}\n"
                    msg += f"Severity: {vuln['severity']}\n"
                    msg += f"First Detected: {vuln['first_seen']}\n"
                    
                    push_wechat_group(msg)
                    last_notified[vuln_id] = current_time
            
            # Get scan status every 5 minutes
            status = get_scan_status()
            time.sleep(300)
            
        except Exception as e:
            print(f"Monitoring error: {str(e)}")
            time.sleep(60)

def main():
    global add_count_suss, error_count, target_scan, scan_label, input_urls, profile_id
    
    # AWVS scanning profiles
    mod_id = {
        "1": "11111111-1111-1111-1111-111111111111",  # Full Scan
        "2": "11111111-1111-1111-1111-111111111112",  # High Risk Vulnerabilities
        "3": "11111111-1111-1111-1111-111111111116",  # XSS Vulnerabilities
        "4": "11111111-1111-1111-1111-111111111113",  # SQL Injection
        "5": "11111111-1111-1111-1111-111111111115",  # Weak Passwords
        "6": "11111111-1111-1111-1111-111111111117",  # Crawl Only
        "7": "11111111-1111-1111-1111-111111111120",  # Malware Scan
        "8": "none",  # Add Only (no scan)
        "9": "apache-log4j",
        "10": "bug-bounty",
        "11": "enhanced-cves",
        "12": "custom",
    }

    if not target_scan:
        print("""Select scan type:
1  [Full Scan]
2  [High Risk Vulnerabilities]
3  [XSS Vulnerabilities]
4  [SQL Injection]
5  [Weak Passwords]
6  [Crawl Only]
7  [Malware Scan]
8  [Add Targets Only]
9  [Apache Log4j]
10 [Bug Bounty]
11 [Enhanced CVEs]
12 [Custom Profile]
""")
    else:
        print("""Scan existing targets:
1  [Full Scan]
2  [High Risk Vulnerabilities]
3  [XSS Vulnerabilities]
4  [SQL Injection]
5  [Weak Passwords]
6  [Crawl Only]
7  [Malware Scan]
9  [Apache Log4j]
10 [Bug Bounty]
11 [Enhanced CVEs]
12 [Custom Profile]
""")

    scan_type = input('Enter selection: ').strip()
    scan_label = input('Scan label (optional): ').strip() or 'Script default label'
    
    is_to_scan = True
    if scan_type == "8":
        is_to_scan = False
        
    # Handle special profiles
    if scan_type == "9":
        profile_id = create_custom_profile("Apache Log4j", [
            "wvs/Scripts/PerFile",
            "wvs/Scripts/PerFolder",
            "wvs/Scripts/PerScheme/ASP_Code_Injection.script"
        ]) or get_profile_id("Apache Log4j")
    elif scan_type == "10":
        profile_id = create_custom_profile("Bug Bounty", [
            "wvs/Scripts/PerFile/Backup_File.script",
            "wvs/Scripts/PerFile/Basic_Auth_Over_HTTP_File.script",
            "wvs/Scripts/PerFile/HTML_Form_In_Redirect_Page.script",
            "wvs/Scripts/PerFile/Hashbang_Ajax_Crawling.script",
            "wvs/Scripts/PerFile/Javascript_AST_Parse.script",
            "wvs/Scripts/PerFile/PHP_SuperGlobals_Overwrite.script",
            "wvs/Scripts/PerFolder/APC.script",
            "wvs/Scripts/PerFolder/ASP-NET_Application_Trace.script",
            "wvs/Scripts/PerFolder/ASP-NET_Debugging_Enabled.script",
            "wvs/Scripts/PerFolder/ASP-NET_Diagnostic_Page.script",
            "wvs/Scripts/PerFolder/Access_Database_Found.script",
            "wvs/Scripts/PerFolder/Apache_Solr.script",
            "wvs/Scripts/PerFolder/Basic_Auth_Over_HTTP.script",
            "wvs/Scripts/PerFolder/Bazaar_Repository.script",
            "wvs/Scripts/PerFolder/CVS_Repository.script",
            "wvs/Scripts/PerFolder/Core_Dump_Files.script",
            "wvs/Scripts/PerFolder/Development_Files.script",
            "wvs/Scripts/PerFolder/Dreamweaver_Scripts.script",
            "wvs/Scripts/PerFolder/Grails_Database_Console.script",
            "wvs/Scripts/PerFolder/HTML_Form_In_Redirect_Page_Dir.script",
            "wvs/Scripts/PerFolder/Http_Verb_Tampering.script",
            "wvs/Scripts/PerFolder/IIS51_Directory_Auth_Bypass.script",
            "wvs/Scripts/PerFolder/JetBrains_Idea_Project_Directory.script",
            "wvs/Scripts/PerFolder/Mercurial_Repository.script",
            "wvs/Scripts/PerFolder/PHPInfo.script",
            "wvs/Scripts/PerFolder/REST_Discovery_And_Audit_Folder.script",
            "wvs/Scripts/PerFolder/Readme_Files.script",
            "wvs/Scripts/PerFolder/SQLite_Database_Found.script",
            "wvs/Scripts/PerFolder/SVN_Repository.script",
            "wvs/Scripts/PerFolder/Trojan_Scripts.script",
            "wvs/Scripts/PerFolder/Weak_Password_Basic_Auth.script",
            "wvs/Scripts/PerFolder/Deadjoe_file.script",
            "wvs/Scripts/PerFolder/Symfony_Databases_YML.script",
            "wvs/Scripts/PerFolder/Nginx_Path_Traversal_Misconfigured_Alias.script",
            "wvs/Scripts/PerFolder/Spring_Security_Auth_Bypass_CVE-2016-5007.script",
            "wvs/Scripts/PostCrawl/Adobe_Flex_Audit.script",
            "wvs/Scripts/PostCrawl/Amazon_S3_Buckets_Audit.script",
            "wvs/Scripts/PostCrawl/Apache_CN_Discover_New_Files.script",
            "wvs/Scripts/PostCrawl/Azure_Blobs_Audit.script",
            "wvs/Scripts/PostCrawl/CKEditor_Audit.script",
            "wvs/Scripts/PostCrawl/CakePHP_Audit.script",
            "wvs/Scripts/PostCrawl/ExtJS_Examples_Arbitrary_File_Read.script",
            "wvs/Scripts/PostCrawl/FCKEditor_Audit.script",
            "wvs/Scripts/PostCrawl/GWT_Audit.script",
            "wvs/Scripts/PostCrawl/Genericons_Audit.script",
            "wvs/Scripts/PostCrawl/Host_Header_Attack.script",
            "wvs/Scripts/PostCrawl/IIS_Tilde_Dir_Enumeration.script",
            "wvs/Scripts/PostCrawl/J2EE_Audit.script",
            "wvs/Scripts/PostCrawl/JAAS_Authentication_Bypass.script",
            "wvs/Scripts/PostCrawl/JBoss_Seam_Remoting.script",
            "wvs/Scripts/PostCrawl/JBoss_Seam_actionOutcome.script",
            "wvs/Scripts/PostCrawl/JSP_Authentication_Bypass.script",
            "wvs/Scripts/PostCrawl/MS15-034.script",
            "wvs/Scripts/PostCrawl/Minify_Audit.script",
            "wvs/Scripts/PostCrawl/OFC_Upload_Image_Audit.script",
            "wvs/Scripts/PostCrawl/PHP_CGI_RCE.script",
            "wvs/Scripts/PostCrawl/PrimeFaces5_EL_Injection.script",
            "wvs/Scripts/PostCrawl/Rails_Audit.script",
            "wvs/Scripts/PostCrawl/Rails_Audit_Routes.script",
            "wvs/Scripts/PostCrawl/Rails_Devise_Authentication_Password_Reset.script",
            "wvs/Scripts/PostCrawl/Server_Source_Code_Disclosure.script",
            "wvs/Scripts/PostCrawl/Session_Fixation.script",
            "wvs/Scripts/PostCrawl/SharePoint_Audit.script",
            "wvs/Scripts/PostCrawl/Struts2_ClassLoader_Manipulation.script",
            "wvs/Scripts/PostCrawl/Struts2_ClassLoader_Manipulation2.script",
            "wvs/Scripts/PostCrawl/Struts2_Development_Mode.script",
            "wvs/Scripts/PostCrawl/Struts2_Remote_Code_Execution.script",
            "wvs/Scripts/PostCrawl/Struts2_Remote_Code_Execution_S2014.script",
            "wvs/Scripts/PostCrawl/Struts2_Remote_Code_Execution_S2045.script",
            "wvs/Scripts/PostCrawl/Struts2_Remote_Code_Execution_S2048.script",
            "wvs/Scripts/PostCrawl/Struts_RCE_S2-052_CVE-2017-9805.script",
            "wvs/Scripts/PostCrawl/Timthumb_Audit.script",
            "wvs/Scripts/PostCrawl/Tiny_MCE_Audit.script",
            "wvs/Scripts/PostCrawl/Uploadify_Audit.script",
            "wvs/Scripts/PostCrawl/WADL_Files.script",
            "wvs/Scripts/PostCrawl/WebDAV_Audit.script",
            "wvs/Scripts/PostCrawl/nginx-redir-headerinjection.script",
            "wvs/Scripts/PostCrawl/phpLiteAdmin_Audit.script",
            "wvs/Scripts/PostCrawl/phpThumb_Audit.script",
            "wvs/Scripts/PostCrawl/tcpdf_Audit.script",
            "wvs/Scripts/WebApps",
            "wvs/RPA/InsecureTransition.js",
            "wvs/RPA/SQL_Statement_In_Comment.js",
            "wvs/RPA/Content_Type_Missing.js",
            "wvs/RPA/Session_Token_In_Url.js",
            "wvs/RPA/Password_In_Get.js",
            "wvs/RPA/Cookie_On_Parent_Domain.js",
            "wvs/RPA/Cookie_Without_HttpOnly.js",
            "wvs/RPA/Cookie_Without_Secure.js",
            "wvs/RPA/Cacheable_Sensitive_Page.js",
            "wvs/RPA/Unencrypted_VIEWSTATE.js",
            "wvs/RPA/SRI_Not_Implemented.js",
            "wvs/RPA/no_https.js",
            "wvs/RPA/Express_Cookie_Session_Weak_Secret.js",
            "wvs/RPA/JWT_Cookie_Audit.js",
            "wvs/RPA/Cookie_Validator.js",
            "wvs/RPA/F5_BIGIP_Cookie_Info_Disclosure.js",
            "wvs/Crawler",
            "wvs/Scripts/PerServer/Same_Site_Scripting.script",
            "wvs/Scripts/PerServer/SSL_Audit.script",
            "wvs/Scripts/PerServer/WAF_Detection.script",
            "wvs/Scripts/PerServer/Version_Check.script",
            "wvs/Scripts/PerServer/Unprotected_phpMyAdmin_Interface.script",
            "wvs/Scripts/PerServer/Track_Trace_Server_Methods.script",
            "wvs/RPA/Express_Express_Session_Weak_Secret.js",
            "wvs/target/ssltest",
			"ovas/"
        ]) or get_profile_id("Bug Bounty")
    elif scan_type == "11":
        profile_id = create_custom_profile("Enhanced CVEs", [
            "wvs/Crawler",
            "wvs/deepscan",
            "ovas/configuration",
            "ovas/fuzzing",
            "ovas/general",
            "ovas/linux",
            "ovas/netware",
            "ovas/rpc",
            "ovas/smb",
            "ovas/web_servers",
            "ovas/windows"
        ]) or get_profile_id("Enhanced CVEs")
    elif scan_type == "12":
        profile_name = input("Enter profile name: ").strip()
        profile_id = get_profile_id(profile_name)
        if not profile_id:
            print(f"Profile '{profile_name}' not found")
            return
    else:
        profile_id = mod_id.get(scan_type)
        
    if not profile_id:
        print("Invalid scan type")
        return
        
    # Process targets
    if not target_scan:
        targets = [t.strip() for t in open(input_urls, 'r', encoding='utf-8').read().split('\n') if t.strip()]
        success_file = open('./add_log/success.txt', 'a', encoding='utf-8')
        error_file = open('./add_log/error_url.txt', 'a', encoding='utf-8')
        
        for target in targets:
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
                
            target_state = scan(awvs_url, target, profile_id, is_to_scan)
            
            if target_state[0] == 1:
                success_file.write(f"{target}\n")
                add_count_suss += 1
                print(f"{target} added to scan queue ({add_count_suss})")
            elif target_state[0] == 2:
                print(f"{target} added without scan")
            else:
                error_file.write(f"{target}\n")
                error_count += 1
                print(f"{target} failed: {target_state[1]} ({error_count})")
                
        success_file.close()
        error_file.close()
        
        print(f"\nSummary: {add_count_suss} added, {error_count} failed")
        push_wechat_group(f"Scan initiated for {add_count_suss} targets\nProfile: {list(mod_id.keys())[list(mod_id.values()).index(profile_id)] if profile_id in mod_id.values() else 'Custom'}")
        
    else:
        scan_url = f"{awvs_url}/api/v1/scans"
        targets = get_target_list()
        
        for target in targets:
            configuration(awvs_url, target['target_id'], target['address'], profile_id)
            data = {
                "target_id": target['target_id'],
                "profile_id": profile_id,
                "incremental": False,
                "schedule": {"disable": False, "start_date": None, "time_sensitive": False}
            }
            try:
                response = requests.post(scan_url, json=data, headers=headers, timeout=30, verify=False)
                if response.status_code == 201:
                    print(f"{target['address']} scan started")
                else:
                    print(f"{target['address']} scan failed: {response.status_code}")
            except Exception as e:
                print(f"{target['address']} exception: {str(e)}")
                
        print(f"\nScan initiated for {len(targets)} targets")
        push_wechat_group(f"Scan initiated for {len(targets)} existing targets")

if __name__ == '__main__':
    # Verify connection first
    if not get_status():
        sys.exit()
        
    print("""
********************************************************************      
Acunetix v25.5 Enhanced Scanner
New Features:
- API Discovery Scanning
- WebSocket Testing
- JWT Scanning
- GraphQL Support
- Critical Vuln Real-time Monitoring
- OpenAPI Specification Support
********************************************************************
1 [Add URLs to AWVS]
2 [Delete All Targets & Scans]
3 [Delete All Scan Tasks]
4 [Scan Existing Targets]
5 [Critical Vuln Monitoring]
6 [Get Scan Status]
    """)
    
    try:
        selection = int(input('Enter selection: '))
    except:
        print("Invalid selection")
        sys.exit()
        
    if selection == 1:
        main()
    elif selection == 2:
        delete_targets()
    elif selection == 3:
        delete_task()
    elif selection == 4:
        target_scan = True
        main()
    elif selection == 5:
        push_wechat_group("Critical vulnerability monitoring started")
        monitor_critical_vulns()
    elif selection == 6:
        while True:
            get_scan_status()
            time.sleep(60)
    else:
        print("Invalid selection")
