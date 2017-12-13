from flask import Blueprint

from principal import acl

from . import oauth

module = Blueprint('dashboard.developers', __name__, url_prefix='/developers')

subviews = [oauth]


@module.route('/')
@acl.allows.requires(acl.is_developer)
def index():
    return 'developer'
