#!/usr/bin/env python3

import os, cgi

def get_var(name: str, def_val: str = ""):
    if name in os.environ:
        return os.environ[name]
    return def_val

name = None
try:
    form = cgi.FieldStorage()
    if 'name' in form:
        name = str(form['name'].value)
except Exception:
    pass

print("Content-Type: application/json\n")
if name:
    print(f"""{{ "{name}" : "{get_var(name, '')}"
    }}""")
else:
    print(f"""{{ "https" : "{get_var('HTTPS', '')}",
  "host" : "{get_var('SERVER_NAME', '')}",
  "protocol" : "{get_var('SERVER_PROTOCOL', '')}",
  "ssl_protocol" : "{get_var('SSL_PROTOCOL', '')}",
  "ssl_cipher" : "{get_var('SSL_CIPHER', '')}"
}}""")

