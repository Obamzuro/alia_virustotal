import http
import requests
import logging
import json
import hashlib
import bitstring
import os

def md5(fileEntity):
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: fileEntity.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()

def upload_file_on_server(filename, file_hash, fileEntity):
    url = "https://te.checkpoint.com/tecloud/api/v1/file/upload"
    params = {
            "request": 
                {
                    "md5": file_hash, "file_name": filename, "file_type": "txt", "features": ["te"], "te":
                    {
                        "reports": ["summary"],
                        "images": 
                        [{
                            "id": "e50e99f3-5963-4573-af9e-e3f4750b55e2",
                            "revision": 1
                        }]
                    }
                }
            }
    headers = {"Authorization": "#######"}
    files = {
            'json': (None, json.dumps(params), 'application/json'),
            'file': (os.path.basename(filename), fileEntity)
            }
    print("\033[1;34;40mUpload file to server\033[0;37;40m")
    responce = requests.post(url, files=files, headers=headers);
    print(responce.content.decode('ascii'))
#    responce = requests.post(url, headers=headers, files=files);
#    print(responce.content)

def check_file_on_server(filename, isUploaded):
    url = "https://te.checkpoint.com/tecloud/api/v1/file/query"
    headers = {"Authorization": "#########"}
    print("\033[1;34;40mQuery server if file has already exists\033[0;37;40m")
    try:
        with open(filename, "rb") as fileEntity:
            file_hash = md5(fileEntity)
            params = { "request": {"md5": file_hash, "file_name": filename }}
            responce = requests.post(url, data=json.dumps(params), headers=headers)
            json_data = responce.json()
            print(responce.content.decode('ascii'))
            status_code = json_data['response']['status']['code']
            if status_code == 1001:
                print("\033[1;32;40mFile was found\033[0;37;40m")
                upload_file_on_server(filename, file_hash, fileEntity)
            elif status_code == 1004:
                print("\033[1;31;40mFile on server didn't found\033[0;37;40m")
                upload_file_on_server(filename, file_hash, fileEntity)
    except FileNotFoundError as fnf_error:
        print(fnf_error)

def debug_http():
    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

debug_http()
filename = input("Type the name of the file to be checked:\n")
check_file_on_server(filename, 0)
