from flask import Flask, request
from Crypto.Random import get_random_bytes

from challenge_31 import insecure_compare
from Utils.Hash import HMAC


app = Flask(__name__)
KEY = get_random_bytes(16)


@app.route('/test')
def validate_signature():
    # parse url
    file = request.args.get('file')
    signature = request.args.get('signature')

    # evaluate HMAC-SHA1
    mac = HMAC.sha1(key=KEY, msg=file.encode()).hex()

    # compare to signature
    flag = insecure_compare(mac, signature, sleep_time=50e-3)

    if flag:
        return 'signature verified', 200
    else:
        return 'signature does not match', 500


if __name__ == '__main__':
    app.run(port=9000)
