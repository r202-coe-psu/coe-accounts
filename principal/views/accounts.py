from flask import Blueprint, render_template, g, url_for, redirect, session
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
    user.save()

def authenticate(name, password):

    from principal.utils.clients import ldap
    ldap_client = ldap.LDAPClient(name, password)

    user = models.User.objects(username=name).first()
    if ldap_client.authenticate():
        if not user:
            data = ldap_client.get_info()
            add_new_user_with_ldap(data)
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
    return redirect(url_for('dashboard.index'))


@module.route("/logout")
@login_required
def logout():
    session.pop('user', None)
    logout_user()
    return redirect(url_for('site.index'))


@module.route('/register', methods=('GET', 'POST'))
def register():
    form = forms.accounts.RegisterForm()
    if not form.validate_on_submit():
        return render_template('/accounts/register.html',
                               form=form)



    response = c.users.create(**form.data)
    if response.is_error:
        return render_template('/accounts/register.html',
                               form=form,
                               errors=response.errors)

    return redirect('dashboard.index')
