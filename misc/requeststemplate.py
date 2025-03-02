# this is just a template to base on some python requests, just quick reference for me to write others

import requests

url = "https://example.com/api/resources"

headers = {
   "Authorization": "<header>",
   "Content-Type":"application/json"
    }

data = {
        "key1":"value1",
        "key2":"value2"
        }

response_get = requests.get(url, headers=headers)

response_post = requests.post(url, headers=headers, json=data)

response_put = requests.put(url, headers=headers, json=data)

response_delete = requests.delete(url, headers=headers)
