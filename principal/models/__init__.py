from .users import User, DataSource
from .oauth import OAuthClient, OAuthGrant, OAuthToken


from flask_mongoengine import MongoEngine

db = MongoEngine()

def init_db(app):
    db.init_app(app) 
