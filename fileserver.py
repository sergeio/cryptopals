import time

from flask import Flask, request
app = Flask(__name__)

import sha1

def get_file_sha(filename):
    with open(filename, 'r') as f:
        return sha1.sha1(f.read())


@app.route("/")
def hello():
    filename = request.args.get('file')
    signature = request.args.get('signature')
    sha = get_file_sha(filename)
    for c1, c2 in zip(str(sha), str(signature)):
        if c1 != c2:
            return '', 500
        time.sleep(5.0 / 1000.0)
    return '', 200

    return "Hello World!"
