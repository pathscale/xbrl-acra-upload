import requests
import base64

get_base_auth = lambda username, password: base64.b64encode('{}:{}'.format(username, password).encode()).decode('utf8')

def auth(client_id, secret_key):
    headers = {
        "cache-control": "no-cache",
        "authorization": "Basic {}".format(get_base_auth(client_id, secret_key)),
        "Accept": "application/json, application/xml, text/json, text/x-json, text/javascript, text/xml",
        "User-Agent": "RestSharp 104.1.0.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "www.apimall.acra.gov.sg",
        "Connection": "Keep-Alive"
    }
    oauth_resp = requests.post('https://www.apimall.acra.gov.sg/authorizeServer/oauth/token',
                               data='grant_type=client_credentials', headers=headers)
    return oauth_resp

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--client-id', action="store", dest="client_id", nargs='?', const=1, required=True)
    parser.add_argument('--secret-key', action="store", dest="secret_key", nargs='?', const=1, required=True)
    args = parser.parse_args()
    resp = auth(args.client_id, args.secret_key)
    print("Response {}: {}".format(resp.status_code, resp.content.decode()))