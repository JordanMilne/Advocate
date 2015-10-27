import hashlib

from flask import Flask, request
import advocate
import requests

app = Flask(__name__)


@app.route('/')
def get_hash():
    url = request.args.get("url")
    if not url:
        return "Please specify a url!"
    try:
        headers = {"User-Agent": "Hashifier 0.1"}
        resp = advocate.get(url, headers=headers)
    except advocate.UnacceptableAddressException:
        return "That URL points to a forbidden resource"
    except requests.RequestException:
        return "Failed to connect to the specified URL"

    return hashlib.sha256(resp.content).hexdigest()

if __name__ == '__main__':
    app.run()
