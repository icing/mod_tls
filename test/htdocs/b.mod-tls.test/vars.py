#!/usr/bin/env python3
import os

print("Content-Type: application/json")
print()
print("""{{ "https" : "{https}",
  "host" : "{server_name}",
  "protocol" : "{protocol}",
  "ssl_protocol" : "{ssl_protocol}"
}}""".format(
    https=os.getenv('HTTPS', ''),
    server_name=os.getenv('SERVER_NAME', ''),
    protocol=os.getenv('SERVER_PROTOCOL', ''),
    ssl_protocol=os.getenv('SSL_PROTOCOL', ''),
))

