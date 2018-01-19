import datetime
import mongoengine as me

from authlib.specs.rfc6749 import ClientMixin


class OAuth2ClientMixin(ClientMixin):
    secret = me.StringField(required=True)
    is_confidential = me.BooleanField(required=True, default=False)
    redirect_uris = me.ListField(me.URLField(required=True))
    default_redirect_uri = me.URLField(required=True)
    allowed_scopes = me.ListField(me.StringField(required=True), required=True)

    created_date = me.DateTimeField(required=True,
                                    default=datetime.datetime.utcnow)
    updated_date = me.DateTimeField(required=True,
                                    default=datetime.datetime.utcnow,
                                    auto_now=True)

    @property
    def client_id(self):
        return self.id

    @property
    def client_secret(self):
        return self.secret

    @classmethod
    def get_by_client_id(cls, client_id):
        return cls.objects.get(id=client_id)

    def get_default_redirect_uri(self):
        return self.default_redirect_uri

    def check_redirect_uri(self, redirect_uri):
        if redirect_uri == self.default_redirect_uri:
            return True
        return redirect_uri in self.redirect_uris

    def check_client_type(self, client_type):
        if client_type == 'confidential':
            return self.is_confidential
        if client_type == 'public':
            return not self.is_confidential
        raise ValueError('Invalid client_type')

    def check_response_type(self, response_type):
        return True

    def check_grant_type(self, grant_type):
        return True

    def check_requested_scopes(self, scopes):
        allowed = set(self.allowed_scopes)
        return allowed.issuperset(set(scopes))


class OAuth2AuthorizationCodeMixin:
    code = me.StringField(unique=True, required=True)
    # client = me.ReferenceField(OAuth2ClientMixin, dbref=True, required=True)

    redirect_uri = me.URLField()
    # scope = me.StringField()
    scopes = me.ListField(me.StringField())
    # expires in 5 minutes by default
    expires_at = me.DateTimeField(
            required=True,
            default=datetime.datetime.utcnow() + datetime.timedelta(minutes=5))

    @property
    def scope(self):
        return ' '.join(self.scopes)

    def is_expired(self):
        return self.expires_at < datetime.datetime.utcnow()


class OAuth2TokenMixin:
    # client = me.ReferenceField(OAuth2ClientMixin, dbref=True, required=True)
    token_type = me.StringField()
    access_token = me.StringField(unique=True, required=True)
    refresh_token = me.StringField(index=True)
    scopes = me.ListField(me.StringField())
    created_at = me.DateTimeField(
            required=True,
            default=datetime.datetime.utcnow)
    expires_in = me.IntField(
            required=True,
            default=0)

    @property
    def scope(self):
        return ' '.join(self.scopes)

    @property
    def expires_at(self):
        expires = self.created_at + datetime.timedelta(minutes=self.expires_in)
        return expires.timestamp()
