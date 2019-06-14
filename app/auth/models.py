import ldap
from flask_wtf import FlaskForm
from wtforms import TextField, PasswordField
from wtforms.validators import InputRequired
from app import db, app
 
fake_users = [
    {'username': 'singulani', 'password': '12345'},
    {'username': 'zeze', 'password': '00000'}
]

 
def get_ldap_connection():
    conn = ldap.initialize(app.config['LDAP_PROVIDER_URL'])
    return conn
 
 
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
 
    def __init__(self, username, password):
        self.username = username
 
    @staticmethod
    def try_login(username, password):
        # conn = get_ldap_connection()
        # conn.simple_bind_s(
        #     'cn=%s,ou=Users,dc=testathon,dc=net' % username,
        #     password
        # )

        for user in fake_users:
            if user.get('username') == username and user.get('password') == password:
                return True

        raise ldap.INVALID_CREDENTIALS

 
    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return self.id
 
 
class LoginForm(FlaskForm):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])