from flask import Blueprint

module = Blueprint('dashboard.admin', __name__, url_prefix='/admin')

@module.route('/')
def index():
    return 'admin'
