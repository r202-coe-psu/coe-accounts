from flask import (Blueprint,
                   render_template,
                   url_for,
                   redirect,
                   session,
                   request)
from flask_login import login_user, logout_user, login_required, current_user

from principal import forms
from principal import models

module = Blueprint('accounts', __name__)


def add_new_user_with_ldap(data):
    attributes = dict(
            first_name='first_name',
            last_name='last_name',
            email='email',
            uid='username'
            )

    user = models.User()
    for k, v in attributes.items():
        if k in data:
            user[v] = data[k]
    data_source = models.DataSource(provider='ldap', data=data)
    user.data_sources.append(data_source)

    if user.username.isdigit():
        user.roles.append('student')

    user.save()
    return user


def authenticate(name, password):

    from principal.utils.clients import ldap
    ldap_client = ldap.LDAPClient(name, password)

    user = models.User.objects(username=name).first()
    if ldap_client.authenticate():
        if not user:
            data = ldap_client.get_info()
            user = add_new_user_with_ldap(data)

        login_user(user)
        return True
    elif user and user.verify_password(password):
        login_user(user)
        return True

    return False


@module.route('/login', methods=('GET', 'POST'))
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    form = forms.accounts.LoginForm()

    if not form.validate_on_submit():
        return render_template('/accounts/login.html',
                               form=form)

    name = form.name.data
    password = form.password.data

    if not authenticate(name, password):
        return render_template('/accounts/login.html',
                               form=form)

    if request.args.get('next', None):
        response = redirect(request.args.get('next'))
        return response

    return redirect(url_for('dashboard.index'))


@module.route("/logout")
@login_required
def logout():
    session.pop('user', None)
    logout_user()
    return redirect(url_for('site.index'))
