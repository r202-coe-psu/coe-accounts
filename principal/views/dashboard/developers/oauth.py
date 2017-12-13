from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user
from flask_allows import Or

from principal import acl
from principal import forms
from principal import models

module = Blueprint('dashboard.developers.oauth', __name__, url_prefix='/oauth')


@module.route('/')
@acl.allows.requires(Or(acl.is_developer, acl.is_admin))
def index():
    oauth_clients = models.OAuthClient.objects(
            user=current_user._get_current_object())
    return render_template('/dashboard/developers/oauth/index.html',
                           oauth_clients=oauth_clients)


@module.route('/create', methods=['GET', 'POST'])
def create():
    form = forms.oauth.OAuthProjectForm()
    if not form.validate_on_submit():
        return render_template('/dashboard/developers/oauth/create.html',
                               form=form)
    
    client = models.OAuthClient(name=form.name.data,
                                description=form.description.data,
                                confidential=form.confidential.data,
                                redirect_uris=form.redirect_uris.data,
                                user=current_user._get_current_object())
    client.save()


    return redirect(url_for('dashboard.developers.oauth.view',
                            client_id=client.id))


@module.route('/update')
def update():
    return 'oauth.update'


@module.route('/<client_id>/delete')
def delete(client_id):
    client = models.OAuthClient.objects(id=client_id,
            user=current_user._get_current_object())
    client.delete()
    return redirect(url_for('dashboard.developers.oauth.index'))


@module.route('/<client_id>')
def view(client_id):
    oauth_client = models.OAuthClient.objects(
            id=client_id,
            user=current_user._get_current_object()).first()
    if not oauth_client:
        return redirect(url_for('dashboard.developers.oath.index'))
        
    return render_template('/dashboard/developers/oauth/view.html',
                           oauth_client=oauth_client)
