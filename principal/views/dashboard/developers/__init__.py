from flask import Blueprint

from principal import acl

from . import oauth2

module = Blueprint('dashboard.developers', __name__, url_prefix='/developers')

subviews = [oauth2]


@module.route('/')
@acl.allows.requires(acl.is_developer)
def index():
    return 'developer'
