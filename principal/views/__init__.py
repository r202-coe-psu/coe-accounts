
from . import site
from . import accounts

from . import dashboard

def register_blueprint(app):
    for view in [site,
                 accounts,
                 dashboard]:
        app.register_blueprint(view.module)
