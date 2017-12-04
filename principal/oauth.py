from datetime import datetime, timedelta
from flask import Blueprint
from flask_oauthlib.provider import OAuth2Provider
from flask_login import current_user, login_required
from . import models

oauth = OAuth2Provider()
module = Blueprint('oauth', __name__, url_prefix='/oauth')

def init_oauth(app):
    oauth.init_app(app)
    app.register_blueprint(module)

@module.route('/authorize', methods=['GET', 'POST'])
@login_required
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = models.Client.objects.get(client_id)
        kwargs['client'] = client
        return render_template('oauthorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@oauth.usergetter
def get_user(username, password, *args, **kwargs):
    user = models.User.objects(username=username).first()
    if user.check_password(password):
        return user
    return None


@oauth.clientgetter
def load_client(client_id):
    return models.OAuthClient.objects.get(client_id)


@oauth.grantgetter
def load_grant(client_id, code):
    return models.OAuthGrant.objects(id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    client = models.OAuthClient.get(client_id)
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


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return models.Token.objects(access_token=access_token).first()
    elif refresh_token:
        return models.Token.objects(refresh_token=refresh_token).first()

@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    user = model.User.objects.get(request.user.id)
    client = models.Client.objects(id=request.client.client_id,
                                   user=user)
    tokens = models.Token.objects(client=client,
                                user=user)
    # make sure that every client has only one token connected to a user
    for token in tokens:
        token.delete()

    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    token = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        scopes=token['scope'],
        expires=expires,
        client=client,
        user=user,
    )
    token.save()
    return token

@module.route('/token', methods=['POST'])
@oauth.token_handler
def access_token():
    return {'version': '0.1.0'}

@module.route('/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token(): pass


