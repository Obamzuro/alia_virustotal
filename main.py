from http import client
from requests import post
import logging
from json import dumps
from hashlib import md5
import os
import time
import re

RED = 0b1
GREEN = 0b10
BLUE = 0b100

API_ID = "####################"

def print_debug(string, color, is_debug=None):
    if is_debug and debug_level == "y" or not is_debug:
        if (color):
            if (color & RED):
                print("\033[1;31;49m", end="")
            elif (color & GREEN):
                print("\033[1;32;49m", end="")
            elif (color & BLUE):
                print("\033[1;34;49m", end="")
        print(string, end="")
        print("\033[0;39;49m")

def md5(file_entity):
    hash_md5 = md5()
    for chunk in iter(lambda: file_entity.read(4096), b""):
        hash_md5.update(chunk)
    file_entity.seek(0)
    return hash_md5.hexdigest()

def response_1001_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    combined_verdict = json_data["response"]["te"]["combined_verdict"]
    if combined_verdict == "malicious":
        print_debug("File is malicious", RED)
    elif combined_verdict == "benign":
        print_debug("File is not malicious", GREEN)

def response_1002_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("File was uploaded successfully", GREEN)
    te_record = json_data["response"]["te"]
    if te_record.get("combined_verdict"):
        if combined_verdict == "malicious":
            print_debug("!File is malicios!", RED)
        elif combined_verdict == "benign":
            print_debug("!File is not malicios!", GREEN)
    else:
        check_file_on_server_uploaded(filename, file_entity, file_hash, te_cookie)

def response_1003_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("Request is pending", BLUE)
    time.sleep(3)

def response_1004_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("File on server didn't found", RED)
    if first_time:
        upload_file_on_server(filename, file_entity, file_hash, te_cookie)

def response_1006_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("File on server didn't found", RED)
    if first_time:
        upload_file_on_server(filename, file_entity, file_hash, te_cookie)

def response_1007_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("File type is illegal.", RED)

def response_1008_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("Request format is not valid. Make sure the request follows this documentation.", RED)

def response_1009_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("There is a temporary error with the service. Try again in few minutes.", RED)

def response_1010_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("Forbidden query request", RED)

def response_1011_status_code(filename, file_entity, file_hash, te_cookie, json_data, first_time):
    print_debug("There is a temporary error with the service. Try again in few seconds.", RED)

status_code_switcher = {
        1001: response_1001_status_code,
        1002: response_1002_status_code,
        1003: response_1003_status_code,
        1004: response_1004_status_code,
        1006: response_1006_status_code,
        1007: response_1007_status_code,
        1008: response_1008_status_code,
        1009: response_1009_status_code,
        1010: response_1010_status_code,
        1011: response_1011_status_code
    }

def check_file_on_server_uploaded(filename, file_entity, file_hash, te_cookie=None):
    url = "https://te.checkpoint.com/tecloud/api/v1/file/query"
    if te_cookie:
        headers = {"Authorization": API_ID, "te_cookie": te_cookie}
    else:
        headers = {"Authorization": API_ID}
    print_debug("Query server for uploaded file", BLUE)
    params = { "request": {"md5": file_hash, "file_name": os.path.basename(filename)}}
    while 1:
        response = post(url, data=dumps(params), headers=headers)
        if (response.status_code == 400):
            print_debug("400 Server Response error (check extension of file)", RED)
        elif (response.status_code == 503):
            print_debug("503 Service Unavailable", BLUE)
            time.sleep(3)
            file_entity.seek(0)
            upload_file_on_server(filename, file_entity, file_hash, te_cookie)
        print_debug(response.content.decode('ascii'), None, 1)
        json_data = response.json()
        first_time = False
        if not te_cookie:
            te_cookie = dict(re.findall(r'(\w+)=([^ ]+);', response.headers.get("Set-Cookie"))).get("te_cookie")
            print_debug("te_cookie = " + te_cookie, None, 1)
            first_time = True
        status_code = json_data['response']['status']['code']
        status_code_switcher.get(status_code)(filename, file_entity, file_hash, te_cookie, json_data, first_time)
        # for pendig request
        if (status_code == 1003):
            continue
        break

def upload_file_on_server(filename, file_entity, file_hash, te_cookie):
    url = "https://te.checkpoint.com/tecloud/api/v1/file/upload"
    params = {
                "request": 
                {
                    "md5": file_hash, "file_name": os.path.basename(filename), "file_type": "application/octet-stream"
                }
            }
    headers = {"Authorization": API_ID, "te_cookie": te_cookie}
    files = {
                'json': (None, json.dumps(params), 'application/json'),
                'file': (os.path.basename(filename), file_entity, "application/octet-stream")
            }
    print_debug("Upload file to server", BLUE)
    response = post(url, files=files, headers=headers);
    if (response.status_code == 400):
        print_debug("400 Server Response error (check extension of file)", RED)
    elif (response.status_code == 503):
        print_debug("503 Service Unavailable", BLUE)
        time.sleep(3)
        file_entity.seek(0)
        upload_file_on_server(filename, file_entity, file_hash, te_cookie)
    json_data = response.json()
    json_data = response.json()
    print_debug(response.content.decode('ascii'), None, 1)
    status_code = json_data['response']['status']['code']
    status_code_switcher.get(status_code)(filename, file_entity, file_hash, te_cookie, json_data, None)

def check_file_on_server(filename):
    try:
        with open(filename, "rb") as file_entity:
            file_hash = md5(file_entity)
            check_file_on_server_uploaded(filename, file_entity, file_hash)
    except json.decoder.JSONDecodeError as json_error:
        print_debug("json_response convert error", RED)
    except Exception as e:
        print_debug(e, RED)

def debug_http(debug_level):
    if (debug_level == "y"):
        client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

filename = input("Type the name of the file to be checked:\n")
debug_level = input("Is debug needed? (y/N) ")
debug_http(debug_level)
check_file_on_server(filename)
