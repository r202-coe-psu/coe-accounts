import uuid
import datetime

import mongoengine as me

from . import authlib_mongoengine as alm
from . import users


class OAuth2Client(me.Document, alm.OAuth2ClientMixin):
    secret = me.UUIDField(required=True,
                          uniqued=True,
                          binary=False,
                          default=uuid.uuid4)

    user = me.ReferenceField(users.User, dbref=True)

    meta = {
        'collection': 'oauth2_clients'
    }

    @property
    def client_secret(self):
        return str(self.secret)


class OAuth2Token(me.Document, alm.OAuth2TokenMixin):
    user = me.ReferenceField(users.User, dbref=True)
    client = me.ReferenceField(OAuth2Client, dbref=True, required=True)

    meta = {
        'collection': 'oauth2_tokens'
    }

    def is_refresh_token_expired(self):
        expired_at = self.created_at + datetime.timedelt(
                seconds=self.expires_in * 2)
        return expired_at < datetime.datetime.now()

    @classmethod
    def query_token(cls, access_token):
        return cls.objects.get(access_token=access_token)


class OAuth2AuthorizationCode(me.Document, alm.OAuth2AuthorizationCodeMixin):

    user = me.ReferenceField(users.User, dbref=True)
    client = me.ReferenceField(OAuth2Client, dbref=True, required=True)
    meta = {
        'collection': 'oauth2_authorization_codes'
        }

    @property
    def client_id(self):
        return self.client.id
