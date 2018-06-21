import datetime
import mongoengine as me

from authlib.specs.rfc6749 import ClientMixin


class OAuth2ClientMixin(ClientMixin):
    secret = me.StringField(required=True)
    issued_at = me.DateTimeField(required=True,
                                 default=datetime.datetime.utcnow)
    expires_at = me.DateTimeField(required=True,
                                  default=datetime.datetime.utcnow() + \
                                          datetime.timedelta(days=300))
    redirect_uris = me.ListField(me.URLField(required=True))
    token_endpoint_auth_method = me.StringField(require=True,
                                                default='client_secret_basic')
    grant_types = me.ListField(me.StringField(required=True))
    response_types = me.ListField(me.StringField(required=True))
    scopes = me.ListField(me.StringField(required=True), required=True)


    created_date = me.DateTimeField(required=True,
                                    default=datetime.datetime.utcnow)
    updated_date = me.DateTimeField(required=True,
                                    default=datetime.datetime.utcnow,
                                    auto_now=True)

    name = me.StringField(required=True)
    description = me.StringField()
    uri = me.StringField()


    def __repr__(self):
        return '<OAuth2ClientMixin: {}>'.format(self.id)

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
        return self.redirect_uris[0]

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_token_endpoint_auth_method(self, method):
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type):
        if self.response_types:
            return response_type in self.response_types
        return False

    def check_grant_type(self, grant_type):
        if self.grant_types:
            return grant_type in self.grant_types
        return False

    def check_requested_scopes(self, scopes):
        allowed = set(self.scopes)
        return allowed.issuperset(set(scopes))


class OAuth2AuthorizationCodeMixin:
    code = me.StringField(unique=True, required=True)

    redirect_uri = me.URLField()
    response_type = me.StringField()
    scopes = me.ListField(me.StringField())
    auth_time = me.DateTimeField(required=True,
                                 default=datetime.datetime.utcnow)

    @property
    def scope(self):
        return ' '.join(self.scopes)

    def get_scope(self):
        return ' '.join(self.scopes)

    def is_expired(self):
        # expires in 5 minutes by default
        return self.auth_time + datetime.timedelta(minutes=5)\
                < datetime.datetime.utcnow()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_auth_time(self):
        return self.auth_time


class OAuth2TokenMixin:
    # client = me.ReferenceField(OAuth2ClientMixin, dbref=True, required=True)
    token_type = me.StringField()
    access_token = me.StringField(unique=True, required=True)
    refresh_token = me.StringField(index=True)
    scopes = me.ListField(me.StringField())
    revoked = me.BooleanField(required=True, default=False)
    issued_at = me.DateTimeField(
            required=True,
            default=datetime.datetime.utcnow)
    expires_in = me.IntField(
            required=True,
            default=0)

    @property
    def scope(self):
        return ' '.join(self.scopes)

    def get_scope(self):
        return ' '.join(self.scopes)

    def get_expires_in(self):
        return self.expires_in.timestamp()

    def get_expires_at(self):
        expires = self.issued_at + datetime.timedelta(minutes=self.expires_in)
        return expires.timestamp()


def create_query_client_func(session, model_class):
    def query_client(client_id):
        return model_class.objects(id=client_id).first()

    return query_client


def create_query_token_func(session, model_class):
    def query_token(access_token):
        return model_class.objects(access_token=access_token).first()
    return query_token
