from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user
from flask_allows import Or

from principal import acl
from principal import forms
from principal import models

module = Blueprint('dashboard.developers.oauth2', __name__, url_prefix='/oauth2')


@module.route('/')
@acl.allows.requires(Or(acl.is_developer, acl.is_admin))
def index():
    oauth2_clients = models.OAuth2Client.objects(
            user=current_user._get_current_object())
    return render_template('/dashboard/developers/oauth2/index.html',
                           oauth2_clients=oauth2_clients)


@module.route('/create', methods=['GET', 'POST'])
def create():
    form = forms.oauth2.OAuth2ProjectForm()
    if not form.validate_on_submit():
        return render_template('/dashboard/developers/oauth2/create.html',
                               form=form)
    
    client = models.OAuth2Client(name=form.name.data,
                                description=form.description.data,
                                redirect_uris=form.redirect_uris.data,
                                scopes=form.scopes.data,
                                response_types=['code'],
                                grant_types=['authorization_code'],
                                user=current_user._get_current_object())
    client.save()


    return redirect(url_for('dashboard.developers.oauth2.view',
                            client_id=client.id))


@module.route('/update')
def update():
    return 'oauth.update'


@module.route('/<client_id>/delete')
def delete(client_id):
    client = models.OAuth2Client.objects(id=client_id,
            user=current_user._get_current_object())
    client.delete()
    return redirect(url_for('dashboard.developers.oauth2.index'))


@module.route('/<client_id>')
def view(client_id):
    oauth2_client = models.OAuth2Client.objects(
            id=client_id,
            user=current_user._get_current_object()).first()
    if not oauth2_client:
        return redirect(url_for('dashboard.developers.oauth2.index'))
        
    return render_template('/dashboard/developers/oauth2/view.html',
                           oauth2_client=oauth2_client)
