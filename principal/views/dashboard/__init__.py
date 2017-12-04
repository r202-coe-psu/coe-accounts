from flask import Blueprint, render_template, g
from flask_login import login_required

from . import admin

module = Blueprint('dashboard', __name__, url_prefix='/dashboard')
subviews = [admin]

def get_blueprints():
    from principal.views import get_subblueprints

    views = [admin]
    blueprints = get_subblueprints(views,
                                   module.url_prefix)

    return blueprints


@module.route('/')
@login_required
def index():
    return render_template('/dashboard/index.html')
