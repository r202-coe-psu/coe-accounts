from flask import Blueprint, render_template


module = Blueprint('dashboard.admin.users',
                   __name__,
                   url_prefix='/users')


@module.route('/index')
def index():
    return render_template()


@module.route('/list')
def list():
    return render_template()
