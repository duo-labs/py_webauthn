from flask import Flask
from flask import Blueprint, render_template, request, redirect, url_for, flash

app = Flask(__name__)


@app.route("/")
def hello_world():
    return render_template("home.html")


if __name__ == "__main__":
    # run flask application
    app.run(debug=True, use_reloader=False, host="0.0.0.0")