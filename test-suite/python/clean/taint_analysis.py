from flask import Flask, request
import sqlite3
import subprocess
import html
import shlex

app = Flask(__name__)
conn = sqlite3.connect(':memory:')

@app.route('/show')
def show_comment():
    comment = html.escape(request.args.get('comment', ''))
    html_body = f"<div class='comment'>{comment}</div>"
    return html_body

def search_user():
    username = request.args.get('user', '')
    sql = "SELECT * FROM users WHERE username = ?"
    return conn.execute(sql, (username,))

def run_ls():
    path = shlex.quote(request.args.get('path', '.'))
    subprocess.run(['ls', path], check=False, timeout=5)

@app.route('/exec')
def run_code():
    return 'disabled'
