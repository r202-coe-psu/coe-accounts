from flask import (Blueprint,
                   current_app,
                   render_template,
                   request,
                   session,
                   redirect,
                   url_for)
from flask_login import current_user
import json

from principal import (forms,
                       models,
                       acl,
                       views)
from principal.utils.clients import ldap

module = Blueprint('dashboard.admin.users',
                   __name__,
                   url_prefix='/users')


@module.route('/')
@acl.allows.requires(acl.is_admin)
def index():
    return render_template('/dashboard/admin/users/index.html')


@module.route('/list')
@acl.allows.requires(acl.is_admin)
def list():
    return render_template('/dashboard/admin/users/list.html')


@module.route('/search', methods=['POST', 'GET'])
@acl.allows.requires(acl.is_admin)
def search():
    form = forms.users.UserSearchForm()

    if not form.validate_on_submit():
        return render_template('/dashboard/admin/users/search.html',
                               form=form)

    username = form.username.data
    users = models.User.objects(username=username)
    return render_template('/dashboard/admin/users/search.html',
                           form=form,
                           users=users)


@module.route('/ldap-import')
@acl.allows.requires(acl.is_admin)
def ldap_import():
    user_cipher_text = session.get('user.{}'.format(current_user.id), None)
    if user_cipher_text is None:
        return 'Cannot find cipher text'

    user_data = json.loads(current_app.crypto.decrypt(user_cipher_text))
    username = user_data.get('username')
    password = user_data.get('password')

    ldap_client = ldap.LDAPClient(username, password)
    ldap_client.authenticate()
    entries = ldap_client.get_all()
    for entry in entries:
        if 'first_name' not in entry or 'uid' not in entry:
            continue
        if 'uid' in entry and entry['uid'] in ['root',
                                              'coe-diradmin',
                                              'testuser']:
            continue

        user = models.User.objects(username=entry['uid']).first()
        if user:
            continue
        views.accounts.add_new_user_with_ldap(entry)

    return redirect(url_for('dashboard.admin.users.index'))


@module.route('/<user_id>/set_role', methods=['GET'])
@acl.allows.requires(acl.is_admin)
def set_role(user_id):
    role = request.args.get('role')
    if role not in acl.roles:
        return 'Cannot set role:', role, 'not allow'

    user = models.User.objects.get(id=user_id)
    if role not in user.roles:
        user.roles.append(role)
        user.save()

    return redirect(url_for('dashboard.admin.users.index'))
