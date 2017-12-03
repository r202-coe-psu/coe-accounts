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
    user = User.query.filter_by(username=username).first()
    if user.check_password(password):
        return user
    return None



@oauth.clientgetter
def load_client(client_id):
    return models.OAuthClient.objects(id=client_id).first()


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
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()

@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(client_id=request.client.client_id,
                                 user_id=request.user.id)
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok

@module.route('/token', methods=['POST'])
@oauth.token_handler
def access_token():
    return {'version': '0.1.0'}

@module.route('/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token(): pass


