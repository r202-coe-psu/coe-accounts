from flask import Blueprint, abort

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
                            id=user.id,
                            username=user.username))


@module.route('/profile')
@require_oauth2('profile')
def profile():
    user = current_token.user
    return render_json(dict(id=user.id,
                            first_name=user.first_name,
                            last_name=user.last_name,
                            email=user.email,
                            username=user.username,
                            roles=user.roles,
                            last_update=user.updated_date))


@module.route('/users/<username>')
@require_oauth2('email')
def user(username):
    if 'admin' not in current_token.user.roles:
        response = render_json({'error': 'Forbidden'})
        response.status_code = 403
        abort(response)

    user = models.User.objects(username=username).first()
    return render_json(dict(id=user.id,
                            first_name=user.first_name,
                            last_name=user.last_name,
                            email=user.email,
                            username=user.username,
                            roles=user.roles,
                            last_update=user.updated_date))
