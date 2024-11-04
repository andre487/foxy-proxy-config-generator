import copy
import hashlib
import json
import logging
import os
from datetime import timedelta

import flask
import flask_login
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.fields.simple import PasswordField
from wtforms.validators import DataRequired

LOGIN_DURATION = 900

app = flask.Flask(__name__)

with open(os.getenv('USERS_FILE_PATH', '../test-data/passwd.json')) as fp:
    try:
        USERS = json.load(fp)
    except Exception:
        logging.error(f'Failed to load passwords file')
        raise

with open(os.getenv('HOSTS_FILE_PATH', '../test-data/hosts-data.json')) as fp:
    try:
        HOSTS = json.load(fp)
    except Exception:
        logging.error(f'Failed to load hosts file')
        raise

is_dev = os.getenv('MODE_DEV') == '1',
secret_key = os.getenv('FL_SECRET_KEY')
if not secret_key:
    if is_dev:
        secret_key = 'TEST'
    else:
        raise Exception('FL_SECRET_KEY is not defined')

app.config.update(
    DEBUG=is_dev,
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    USE_SESSION_FOR_NEXT=True,
)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Login is required'


class LoginForm(FlaskForm):
    name = StringField('Login', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def load_user(user_id):
    try:
        name_hash = hashlib.sha256(user_id.encode('utf8')).hexdigest()
    except UnicodeError:
        flask.abort(400)

    if name_hash not in USERS:
        return None

    user = User()
    user.id = user_id
    return user


@app.route('/', methods=('GET', 'POST'))
def index():
    form = LoginForm()
    if form.validate_on_submit():
        name = form.name.data
        password = form.password.data
        try:
            name_hash = hashlib.sha256(name.encode('utf8')).hexdigest().encode()
        except UnicodeError:
            flask.abort(flask.Response('Invalid name', status=400))

        expected_password_hash = None
        for stored_name, stored_password in USERS.items():
            if name_hash == stored_name.encode():
                expected_password_hash = stored_password

        if not expected_password_hash:
            flask.abort(flask.Response('Unknown user', status=403))

        exp_pass_data = expected_password_hash.split(':')
        if len(exp_pass_data) != 2:
            flask.abort(flask.Response('Wrong stored password', status=500))

        try:
            salt = bytes.fromhex(exp_pass_data[0])
        except ValueError:
            flask.abort(flask.Response('Wrong stored salt', status=500))

        actual_password_hash = hashlib.pbkdf2_hmac('sha512', password.encode('utf8'), salt, 256_000)
        if f'{salt.hex()}:{actual_password_hash.hex()}' != expected_password_hash:
            flask.abort(flask.Response('Wrong password', status=403))

        user = User()
        user.id = name
        flask_login.login_user(user, duration=timedelta(seconds=LOGIN_DURATION), remember=False)

        data = {'data': []}
        for host_data in HOSTS:
            host_data_copy = copy.deepcopy(host_data)

            host_name = host_data_copy.get('hostname')
            if not host_name:
                continue
            host_data_copy.setdefault('active', True)
            host_data_copy.setdefault('title', host_name)
            host_data_copy.setdefault('type', 'https')
            host_data_copy.setdefault('port', '443')
            host_data_copy['username'] = form.name.data
            host_data_copy['password'] = form.password.data

            data['data'].append(host_data_copy)
            return flask.render_template('config.html', conf=json.dumps(data, indent=2))

    return flask.render_template('login.html', form=form)


if __name__ == '__main__':
    app.run(port=8000)
