# this model came from
# https://flask-oauthlib.readthedocs.io/en/latest/oauth2.html
# modify for mongoengine

from .users import User
import mongoengine as me

class OAuthClient(me.Document):
    # human readable name, not required
    name = me.StringField()

    # human readable description, not required
    description = me.StringField()

    # creator of the client, not required
    user = me.ReferenceField(User, dbref=True)
    # required if you need to support client credential

    secret = me.StringField(required=True, unique=True, index=True)

    # public or confidential
    is_confidential = me.BooleanField()

    redirect_uris = me.ListField(me.URLField())
    default_scopes = me.ListField(me.StringField())

    meta = {'collection': 'oauth_clients'}

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]


class OAuthGrant(me.Document):

    user = me.ReferenceField(User, dbref=True)
    client = me.ReferenceField(OAuthClient, dbref=True)
    code = me.StringField(index=True, required=True)

    redirect_uri = me.URLField()
    expires = me.DateTimeField()

    scopes = me.ListField(me.StringField())

    meta = {'collection': 'oauth_grants'}


class OAuthToken(me.Document):
    client = me.ReferenceField(OAuthClient, dbref=True)
    user = me.ReferenceField(User, dbref=True)

    # currently only bearer is supported
    token_type = me.StringField()

    access_token = me.StringField(unique=True)
    refresh_token = me.StringField(unique=True)
    expires = me.DateTimeField()
    scopes = me.ListField(me.StringField())

    meta = {'collection': 'oauth_tokens'}
