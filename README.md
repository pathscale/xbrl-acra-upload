# xbrl-acra-upload
xbrl acra upload for osx or linux

This tool is meant for IT Admin or those with a strong technical background.

# External dependencies
You can obtain client id , secret key and other parameters from
https://www.apimall.acra.gov.sg/


# Dependencies
python3 installed

python3 -m pip install requests

python3 -m pip install netifaces



# Usage
./xbrl_upload.py --help

usage: xbrl_upload.py

    --client-id [CLIENT_ID]

    --secret-key [SECRET_KEY]

    --client-name [CLIENT_NAME]

    --email [EMAIL]

    --file [FILE]

optional arguments:

  -h, --help            show this help message and exit
