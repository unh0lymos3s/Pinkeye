from flask import Flask, request
import os
import sqlite3

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection: tainted HTTP param flows straight into os.system.
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # SQL injection: tainted param concatenated into the query.
    conn.execute("SELECT * FROM users WHERE id = '" + uid + "'")
    return "ok"
