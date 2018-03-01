from flask import Blueprint, render_template

from principal import acl
from . import users

module = Blueprint('dashboard.admin', __name__, url_prefix='/admin')

subviews = [users]

@module.route('/')
@acl.allows.requires(acl.is_admin)
def index():
    return render_template('/dashboard/admin/index.html')
