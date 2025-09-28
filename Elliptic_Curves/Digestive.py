### SOURCE

import hashlib
import json
import string
from ecdsa import SigningKey

SK = SigningKey.generate() # uses NIST192p
VK = SK.verifying_key


class HashFunc:
    def __init__(self, data):
        self.data = data

    def digest(self):
        # return hashlib.sha256(data).digest()
        return self.data



# @chal.route('/digestive/sign/<username>/')
def sign(username):
    sanitized_username = "".join(a for a in username if a in string.ascii_lowercase)
    msg = json.dumps({"admin": False, "username": sanitized_username})
    signature = SK.sign(
        msg.encode(),
        hashfunc=HashFunc,
    )

    # remember to remove the backslashes from the double-encoded JSON
    return {"msg": msg, "signature": signature.hex()}


# @chal.route('/digestive/verify/<msg>/<signature>/')
def verify(msg, signature):
    try:
        VK.verify(
            bytes.fromhex(signature),
            msg.encode(),
            hashfunc=HashFunc,
        )
    except:
        return {"error": "Signature verification failed"}

    verified_input = json.loads(msg)
    if "admin" in verified_input and verified_input["admin"] == True:
        return {"flag": FLAG}
    else:
        return {"error": f"{verified_input['username']} is not an admin"}

### SOLUTION

# The signing algorithm takes the hash of the message H(m) and truncates it. It only uses 
# the first (~200) bits and ignores the rest of H(m). But, in this scheme H(m) = m, so two 
# messages that have the same prefix share their sets of valid signatures.

# Now, if we declare one parameter twice in a string that will be parsed to a json, its resulting
# dictionary will have the value that was declared last. For instance, json.loads('{"a": 1, "a": 2}')
# gives the object {"a": 2}.

# With these two facts, we can gather a signature s for any username (since the bit-length of the prefix 
# '{"admin": false, "username":' is more than enough for the truncation, the scheme doesn't even consider 
# the username) and then just verify s along with the message:
msg = '{"admin": false, "username": "", "admin": true}'

# Sources:
# https://datatracker.ietf.org/doc/html/draft-ietf-pkix-sha2-dsa-ecdsa-01#page-4
# https://crypto.stackexchange.com/questions/59202/what-is-the-maximum-message-size-when-using-ecdsa-specifically-secp256k1
