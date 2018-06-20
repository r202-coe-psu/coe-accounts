from flask import Blueprint, request, render_template
from flask_login import current_user, login_required

from authlib.flask.oauth2 import (AuthorizationServer,
                                  ResourceProtector,
                                  current_token)

from authlib.specs.rfc6749 import grants 
from authlib.specs.rfc7009 import RevocationEndpoint as _RevocationEndpoint
from authlib.specs.rfc6750 import BearerTokenValidator

from authlib.common.security import generate_token

from . import models

module = Blueprint('oauth2', __name__, url_prefix='/oauth2')


def query_token(access_token):
    return models.OAuth2Token.objects.get(access_token=access_token)


def query_client(client_id):
    # return models.OAuth2Client.objects(id=client_id).first()
    c = models.OAuth2Client.objects(id=client_id).first()

    print('ccc',c)
    return c

def save_token(token, request):
    user = request.user
    # if request.user:
    #     user_id = request.user.get_user_id()
    # else:
    #     # client_credentials grant_type
    #     user_id = request.client.user_id
    #     # or, depending on how you treat client_credentials
    # user = models.User.objects.get(id=user_id)

    ctoken = token.copy()
    ctoken.pop('scope')
    item = models.OAuth2Token(
        client=request.client,
        user=user,
        scopes=[s.strip() for s in token.get('scope', '').split(' ')],
        **ctoken
    )
    item.save()


class PrincipalBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return models.OAuth2Token.objects(access_token=token_string).first()

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return token.revoked

ResourceProtector.register_token_validator(PrincipalBearerTokenValidator())
require_oauth2 = ResourceProtector()


server = AuthorizationServer()

def init_oauth(app):
    print('query_client=query_client,', query_client)
    server.init_app(app, query_client=query_client, save_token=save_token)

    server.register_grant(AuthorizationCodeGrant)
    # server.register_grant(grants.ImplicitGrant)
    # server.register_grant(PasswordGrant)
    # server.register_grant(ClientCredentialsGrant)
    server.register_grant(RefreshTokenGrant)
    server.register_endpoint(RevocationEndpoint)

    app.register_blueprint(module)


@module.route('/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    if request.method == 'GET':
        grant = server.validate_consent_request(end_user=current_user)
        return render_template(
            '/oauth2/authorize.html',
            grant=grant,
            user=current_user,
        )

    confirmed = request.form['confirm']
    user = None

    if confirmed:
        user = current_user._get_current_object()

    return server.create_authorization_response(grant_user = user)


@module.route('/token', methods=['POST'])
def issue_token():
    print('issue token')
    return server.create_token_response()


@module.route('/token/revoke', methods=['POST'])
def revoke_token():
    print('revoke token')
    return server.create_endpoint_response(RevocationEndpoint.ENDPOINT_NAME)


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    def create_authorization_code(self, client, user, request):
        # you can use other method to generate this code
        code = generate_token(48)
        item = models.OAuth2AuthorizationCode(
            code=code,
            client=client,
            redirect_uri=request.redirect_uri,
            scopes=[s.strip() for s in request.scope.split(' ')],
            user=user,
        )
        item.save()

        return code

    def parse_authorization_code(self, code, client):
        print('parse hear')
        item = models.OAuth2AuthorizationCode.objects.get(
                code=code,
                client=client)
        print('parse item', item)
        if item and not item.is_expired():
            print('code not expired')
            return item

        print('code expired')

    def delete_authorization_code(self, authorization_code):
        authorization_code.delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user
        # return models.User.objects.get(authorization_code.user_id)

    # def create_access_token(self, token, client, authorization_code):
    #     import copy
    #     print('begin create access token')
    #     access_token = copy.copy(token)
    #     access_token.pop('scope')
    #     item = models.OAuth2Token(
    #         client=client,
    #         user=authorization_code.user,
    #         scopes=[s.strip() for s in token.get('scope', '').split(' ')],
    #         **access_token
    #     )

    #     item.save()
    #     # we can add more data into token
    #     token['user_id'] = authorization_code.user.id
    #     print('end create access token')


class RefreshTokenGrant(grants.RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic', 'client_secret_post'
    ]

    def authenticate_refresh_token(self, refresh_token):
        item = models.OAuth2Token.objects(refresh_token=refresh_token).first()
        # define is_refresh_token_expired by yourself
        if item and not item.is_refresh_token_expired():
            return item

    def authenticate_user(self, credential):
        return credential.user


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

    def revoke_token(self, token):
        token.revoked = True
        token.save()

    def invalidate_token(self, token):
        token.delete()


