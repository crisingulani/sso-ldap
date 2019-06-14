import ldap
from flask import (
    request, render_template, flash,
    redirect, url_for, Blueprint, g,
    Response, abort  
)
from flask_login import (
    current_user, login_user,
    logout_user, login_required
)
from app import login_manager, db, logger
from app.auth.models import User, LoginForm
from urllib.parse import urlparse, urljoin

auth = Blueprint('auth', __name__)



def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def authenticate():
    """Sends a 401 response """
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401, {})


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
 
 
@auth.before_request
def get_current_user():
    g.user = current_user
 
 
@auth.route('/')
@auth.route('/home')
# @login_required
def home():
    return Response('Success OK', 200, {})
    # return render_template('home.html')

@auth.route('/check', methods=['GET'])
def check():
    print('--> HEADERS')
    print(request.headers)
    logger.info(request.headers)
    print('--> REFERRER')
    logger.info(request.referrer)

    if current_user.is_authenticated:
        flash('You are already logged in.')
        return Response('You are already logged in. (by login check)', 200, {})

    return authenticate()
 
@auth.route('/login', methods=['GET', 'POST'])
def login():
    print('--> HEADERS')
    print(request.headers)
    print('--> REFERRER')
    print(request.referrer)

    if current_user.is_authenticated:
        flash('You are already logged in.')
        return Response('You are already logged in. (by login page)', 200, {})
 
    form = LoginForm(request.form)
 
    if request.method == 'POST' and form.validate():
        username = request.form.get('username')
        password = request.form.get('password')
 
        try:
            User.try_login(username, password)
        except ldap.INVALID_CREDENTIALS:
            flash(
                'Invalid username or password. Please try again.',
                'danger')
            return render_template('login.html', form=form)
 
        user = User.query.filter_by(username=username).first()
 
        if not user:
            user = User(username, password)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        flash('You have successfully logged in.', 'success')

        
        # # is_safe_url should check if the url is safe for redirects.
        # # See http://flask.pocoo.org/snippets/62/ for an example.

        # if request.referrer:
        #     if not is_safe_url(request.referrer):
        #         return abort(400)
        #     return redirect(request.referrer)
            
        return Response('Login successful by login page', 200, {})
 
    if form.errors:
        flash(form.errors, 'danger')
 
    return render_template('login.html', form=form)
 
 
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
