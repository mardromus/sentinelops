# vulnerable-shop worker: INTENTIONALLY INSECURE demo for SentinelOps. Do not deploy.
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect("shop.db")


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM orders WHERE customer = '{customer}'")
    return {"orders": cur.fetchall()}


@app.route("/import", methods=["POST"])
def import_orders():
    batch = pickle.loads(request.data)
    return {"imported": len(batch)}


@app.route("/config", methods=["POST"])
def load_config():
    cfg = yaml.load(request.data)
    return {"keys": list(cfg)}


@app.route("/report")
def report():
    name = request.args.get("name")
    subprocess.run(f"tar czf /tmp/{name}.tgz /var/reports", shell=True)
    return {"ok": True}


def notify(url, payload):
    return requests.post(url, json=payload, verify=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
