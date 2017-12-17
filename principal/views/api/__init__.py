from flask import Blueprint, request, jsonify

from principal.renderers import render_json
from principal.oauth import oauth2
from principal import models


module = Blueprint('api', __name__, url_prefix='/api')


@module.route('/email')
@oauth2.require_oauth('email')
def email():
    user = request.oauth.user
    return render_json(dict(email=user.email,
                            username=user.username))


@module.route('/me')
@oauth2.require_oauth('me')
def me():
    user = request.oauth.user
    return render_json(dict(id=user.id,
                            first_name=user.first_name,
                            last_name=user.last_name,
                            email=user.email,
                            username=user.username,
                            roles=user.roles,
                            last_update=user.updated_date))


@module.route('/user/<username>')
@oauth2.require_oauth('email')
def user(username):
    user = models.User.objects(username=username).first()
    return jsonify(email=user.email, username=user.username)
