from datetime import datetime, timedelta
from flask import Blueprint, request, render_template, session
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.contrib.oauth2 import bind_cache_grant
from flask_login import current_user, login_required
from . import models

oauth2 = OAuth2Provider()
module = Blueprint('oauth2', __name__, url_prefix='/oauth2')

def init_oauth(app):
    oauth2.init_app(app)
    app.register_blueprint(module)

@module.route('/authorize', methods=['GET', 'POST', 'HEAD'])
@login_required
@oauth2.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = models.OAuthClient.objects.get(id=client_id)
        kwargs['client'] = client
        return render_template('/oauth/authorize.html', **kwargs)

    if request.method == 'HEAD':
        response = make_response('', 200)
        response.headers['X-Client-ID'] = kwargs.get('client_id')
        return response

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@oauth2.usergetter
def get_user(username, password, *args, **kwargs):
    user = models.User.objects(username=username).first()
    if user.check_password(password):
        return user
    return None


@oauth2.clientgetter
def load_client(client_id):
    return models.OAuthClient.objects.get(id=client_id)


@oauth2.grantgetter
def load_grant(client_id, code):
    client = models.OAuthClient.objects.get(id=client_id)
    grant = models.OAuthGrant.objects(client=client, code=code).first()
    return grant


@oauth2.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    client = models.OAuthClient.objects.get(id=client_id)
    grant = models.OAuthGrant(
        client=client,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        scopes=request.scopes,
        user=current_user._get_current_object(),
        expires=expires
    )
    grant.save()

    return grant


@oauth2.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return models.OAuthToken.objects(access_token=access_token).first()
    elif refresh_token:
        return models.OAuthToken.objects(refresh_token=refresh_token).first()
    return None

@oauth2.tokensetter
def save_token(token, request, *args, **kwargs):
    user = models.User.objects.get(id=request.user.id)
    client = models.OAuthClient.objects(id=request.client.client_id,
                                   user=user).first()
    tokens = models.OAuthToken.objects(client=client,
                                user=user).all()
    # make sure that every client has only one token connected to a user
    for t in tokens:
        t.delete()

    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    new_token = models.OAuthToken(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        scopes=token['scope'].split(),
        expires=expires,
        client=client,
        user=user,
    )
    new_token.save()
    return new_token

@module.route('/token', methods=['GET', 'POST'])
@oauth2.token_handler
def access_token():
    return {}
    # return {'version': '0.1.0', }

@module.route('/revoke', methods=['POST'])
@oauth2.revoke_handler
def revoke_token():
    pass


