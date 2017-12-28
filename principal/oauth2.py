from flask import Blueprint, request, render_template
from flask_login import current_user, login_required

from authlib.flask.oauth2 import (AuthorizationServer,
                                  ResourceProtector)

from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    ImplicitGrant as _ImplicitGrant,
    ResourceOwnerPasswordCredentialsGrant as _PasswordGrant,
    ClientCredentialsGrant as _ClientCredentialsGrant,
    RefreshTokenGrant as _RefreshTokenGrant,
)
from authlib.specs.rfc7009 import RevocationEndpoint as _RevocationEndpoint

from authlib.common.security import generate_token

from . import models

module = Blueprint('oauth2', __name__, url_prefix='/oauth2')

server = AuthorizationServer(models.OAuth2Client)


def query_token(access_token):
    return models.OAuth2Token.objects.get(access_token=access_token)


require_oauth2 = ResourceProtector(query_token)


def init_oauth(app):
    server.init_app(app)

    server.register_grant_endpoint(AuthorizationCodeGrant)
    server.register_grant_endpoint(ImplicitGrant)
    server.register_grant_endpoint(PasswordGrant)
    server.register_grant_endpoint(ClientCredentialsGrant)
    server.register_grant_endpoint(RefreshTokenGrant)
    server.register_revoke_token_endpoint(RevocationEndpoint)

    app.register_blueprint(module)


@module.route('/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    if request.method == 'GET':
        grant = server.validate_authorization_request()
        return render_template(
            '/oauth2/authorize.html',
            grant=grant,
            user=current_user,
        )
    confirmed = request.form['confirm']
    if confirmed:
        # granted by resource owner
        return server.create_authorization_response(
                current_user._get_current_object())
    # denied by resource owner
    return server.create_authorization_response(None)


@module.route('/token', methods=['POST'])
def issue_token():
    return server.create_token_response()


@module.route('/revoke', methods=['POST'])
def revoke_token():
    return server.create_revocation_response()


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def create_authorization_code(self, client, user, **kwargs):
        # you can use other method to generate this code
        code = generate_token(48)
        item = models.OAuth2AuthorizationCode(
            code=code,
            client=client,
            redirect_uri=kwargs.get('redirect_uri', ''),
            scope=kwargs.get('scope', ''),
            user=user,
        )
        item.save()

        return code

    def parse_authorization_code(self, code, client):
        item = models.OAuth2AuthorizationCode.objects.get(
                code=code,
                client=client)

        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()

    def create_access_token(self, token, client, authorization_code):
        item = models.OAuth2Token(
            client=client,
            user=authorization_code.user,
            **token
        )

        item.save()
        # we can add more data into token
        token['user_id'] = authorization_code.user.id


# implicit_grant
class ImplicitGrant(_ImplicitGrant):
    def create_access_token(self, token, client, grant_user, **kwargs):
        item = models.OAuth2Token(
            client_id=client.client_id,
            user_id=grant_user.id,
            **token
        )

        item.save()


# password_grant
class PasswordGrant(_PasswordGrant):
    def authenticate_user(self, username, password):
        user = models.User.get(username=username)
        if user.check_password(password):
            return user

    def create_access_token(self, token, client, user, **kwargs):
        item = models.OAtuth2Token(
            client=client,
            user=user,
            **token
        )
        item.save()


# client_credentials_grant
class ClientCredentialsGrant(_ClientCredentialsGrant):
    def create_access_token(self, token, client):
        item = models.OAuth2Token(
            client=client,
            user=client.user,
            **token
        )
        item.save()


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_token(self, refresh_token):
        item = models.OAuth2Token.objects(refresh_token=refresh_token).first()
        # define is_refresh_token_expired by yourself
        if item and not item.is_refresh_token_expired():
            return item

    def create_access_token(self, token, authenticated_token):
        item = models.OAuth2Token(
            client=authenticated_token.client,
            user=authenticated_token.user,
            **token
        )
        # issue a new token to replace the old one
        item.save()
        authenticated_token.delete()


class RevocationEndpoint(_RevocationEndpoint):
    def query_token(self, token, token_type_hint, client):
        q = models.OAuth2Token.objects(client=client)
        if token_type_hint == 'access_token':
            return q.filter_by(access_token=token).first()
        elif token_type_hint == 'refresh_token':
            return q.filter_by(refresh_token=token).first()
        # without token_type_hint
        item = q.filter_by(access_token=token).first()
        if item:
            return item
        return q.filter_by(refresh_token=token).first()

    def invalidate_token(self, token):
        token.delete()
