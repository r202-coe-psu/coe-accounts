from flask import Blueprint, render_template

from principal import forms

module = Blueprint('dashboard.admin.users',
                   __name__,
                   url_prefix='/users')


@module.route('/')
def index():
    return render_template('/dashboard/admin/users/index.html')


@module.route('/list')
def list():
    return render_template('/dashboard/admin/users/list.html')


@module.route('/search', methods=['POST', 'GET'])
def search():
    form = forms.ldap_users.LDAPUserSearchForm()

    if not form.validate_on_submit():
        return render_template('/dashboard/admin/users/search.html',
                               form=form)

    print('data', form.data)
    return render_template('/dashboard/admin/users/search.html',
                           form=form)
