from flask import Blueprint, request, jsonify

from principal.renderers import render_json
from principal.oauth2 import require_oauth2
from principal import models

from authlib.flask.oauth2 import current_token


module = Blueprint('api', __name__, url_prefix='/api')


@module.route('/email')
@require_oauth2('email')
def email():
    user = current_token.user
    return render_json(dict(email=user.email,
                            username=user.username))


@module.route('/me')
@require_oauth2('email')
def me():
    user = current_token.user
    return render_json(dict(id=user.id,
                            first_name=user.first_name,
                            last_name=user.last_name,
                            email=user.email,
                            username=user.username,
                            roles=user.roles,
                            last_update=user.updated_date))


@module.route('/user/<username>')
@require_oauth2('email')
def user(username):
    user = models.User.objects(username=username).first()
    return jsonify(email=user.email, username=user.username)
