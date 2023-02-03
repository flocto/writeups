from flask import Flask, request
import os

app = Flask(__name__)


@app.post("/echo")
def echo():
    data = request.stream.read()
    # print(data)
    return data


@app.route("/flag", methods=["FLAG_PLEASE"])
def flag():
    print(request.headers)
    return os.environ.get("FLAG", "flag{test_flag}")

# gunicorn -k gevent --keep-alive 1 --bind 0.0.0.0:7777 api:app
# app.run(host="localhost", port=8887)