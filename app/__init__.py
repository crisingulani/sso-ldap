from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager 
import logging
from logging.handlers import RotatingFileHandler
 
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_SECRET_KEY'] = 'crcrcrcrscsgshsjsascasasashalskja'
app.config['LDAP_PROVIDER_URL'] = 'ldap://ldap.testathon.net:389/'
app.config['LDAP_PROTOCOL_VERSION'] = 3
db = SQLAlchemy(app)
 
app.secret_key = 'batman batman batman'

handler = RotatingFileHandler('sso.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

logger = app.logger

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
 
from app.auth.views import auth
app.register_blueprint(auth)

db.create_all()
