import base64, email, hmac, hashlib, urllib
import requests,json, time, sys, six
import datetime

"""
Initiate a sync to create, update, or mark for deletion 
the user specified by username against the directory specified 
by the directory_key. The directory_key for a directory can be 
found by navigating to Users → Directory Sync in the Duo Admin Panel, 
and then clicking on the configured directory. Learn more about 
syncing individual users from Active Directory, OpenLDAP, or 
Azure Active Directory. Requires "Grant write resource" API permission.

"""

Duo_directory_key= "XXXXXXXX"


## Admin API
api_ikey="XX..."
api_skey="XXXX........"
duo_host="api-XXXXXXX.duosecurity.com"


# Disable cert warning
requests.packages.urllib3.disable_warnings()

""" necessary headers for Duo """
duo_headers = {'Content-Type':'application/x-www-form-urlencoded', 
            'User-Agent': 'Duo API Python/4.2.3',
            'Host':duo_host}

def encode_headers(params):
    """ encode headers """
    encoded_headers = {}
    for k, v in params.items():
        if isinstance(k, six.text_type):
            k = bytes(k.encode())
        if isinstance(v, six.text_type):
            v = v.encode('ascii')
        encoded_headers[k] = v
    return encoded_headers 


def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z

def sign(method, host, path, params, skey, ikey):
       # create canonical string
        now = email.utils.formatdate()
        canon = [now, method.upper(), host.lower(), path]
        args = []
        for key in sorted(params.keys()):
            val = params[key]
            #if isinstance(val, unicode):
            #    val = val.encode("utf-8")
            args.append(
                '%s=%s' % (urllib.parse.quote(key, '~'), urllib.parse.quote(val, '~')))
        canon.append('&'.join(args))
        canon = '\n'.join(canon)
        # sign canonical string
        sig = hmac.new(skey.encode(), canon.encode(), hashlib.sha1)
        auth = '%s:%s' % (ikey, sig.hexdigest())

        # return headers
        return {'Date': now, 'Authorization': 'Basic %s' % base64.b64encode(auth.encode()).decode()}


def AD_sync_per_user(directory_key, username):
    service_url= "/admin/v1/users/directorysync/"+directory_key+"/syncuser"
    post_data= {"username": username}  
    params1= sign("POST", duo_host, service_url, post_data, api_skey, api_ikey)
    params2= merge_two_dicts(duo_headers, params1)
    encoded_headers = encode_headers(params2)
    response=requests.post(url="https://"+duo_host+service_url, headers=encoded_headers, data=post_data,verify=False)
    print(json.dumps(response.json(),indent=4,sort_keys=True))
    res=response.json()
    return res


if __name__ == "__main__":
    print("AD sync per user v1.0")
    if len(sys.argv) != 2:
        print("HOW TO USE:")
        print("python3 ad_sync_per_user.py username" )
        exit()
    AD_sync_per_user(Duo_directory_key, sys.argv[1])


    
