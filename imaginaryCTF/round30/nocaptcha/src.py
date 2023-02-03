#!/usr/bin/env python
from flask import (
    Flask,
    session,
    request,
    Response,
    render_template,
    jsonify,
    make_response,
)
from flask.sessions import SecureCookieSessionInterface
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired
from redis import Redis
import requests
import uuid
import os

app = Flask(__name__, template_folder="/app")
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_REDIS"] = Redis.from_url(url=os.environ["REDIS_URL"])


class CaptchaForm(FlaskForm):
    answer = StringField("Enter the answer:", validators=[DataRequired()])


@app.route("/", methods=["GET", "POST"])
def index():
    if session.get("id") == None:
        session["id"] = str(uuid.uuid4())
    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    session_cookie = session_serializer.dumps(dict(session))
    response = make_response()
    headers = {
        "cookie": f"{app.session_cookie_name}={session_cookie}; Path=/; HttpOnly"
    }
    form = CaptchaForm()
    if form.validate_on_submit():
        res = requests.post(
            "https://nocapcaptcha.fly.dev/captcha",
            json={"answer": form.answer.data},
            headers=headers,
        )
        result = res.json().get("result")
        if session.get("count", 0) > 2:
            response.data = os.environ["FLAG"]
            return response

        if result == "success":
            response.data = "success"
            session["count"] = session.get("count", 0) + 1
        else:
            response.data = "cap"
        return response

    res = requests.get("https://nocapcaptcha.fly.dev/captcha", headers=headers).json()
    session["cap"] = res.get("cap")
    image = res.get("image")
    response.data = render_template("index.html", form=form, image=image)
    return response


@app.route("/source")
def source():
    with open(__file__, "r") as f:
        source = f.read()
        return Response(source, mimetype="text/plain")


if __name__ == "__main__":
    app.run("0.0.0.0", 5000)