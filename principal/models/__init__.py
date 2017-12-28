from .users import User, DataSource
from .oauth2 import OAuth2Client, OAuth2Token, OAuth2AuthorizationCode


from flask_mongoengine import MongoEngine

db = MongoEngine()

def init_db(app):
    db.init_app(app)
