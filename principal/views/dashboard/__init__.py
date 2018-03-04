from flask import Blueprint, render_template
from flask_login import login_required

from . import admin
from . import developers


module = Blueprint('dashboard', __name__, url_prefix='/dashboard')
subviews = [admin, developers]


@module.route('/')
@login_required
def index():
    return render_template('/dashboard/index.html')
