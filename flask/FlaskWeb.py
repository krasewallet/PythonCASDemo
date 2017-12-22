#!python2
#coding:utf-8
# encoding: utf-8
from flask import Flask, Blueprint
from eduSSO import (CAS,login_required)
app = Flask(__name__)
CAS(app) 
app.config['CAS_SERVER_HOST'] = 'https://test.open.changyan.com' 
app.config['CAS_LOGIN_URL'] = "https://test.pass.changyan.com/login"
app.config['CAS_AFTER_LOGIN'] = 'http://test.webtools.changyan.cn:5000'
app.config['CAS_AFTER_LOGOUT'] = 'http://test.webtools.changyan.cn:5000'
app.config['SECRET_KEY'] = 'zyjxtpc'
@app.route('/')
@login_required
def test():
    return "yes , you are allowed"
if __name__ == "__main__":
    app.run()
