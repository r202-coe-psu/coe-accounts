from flask_wtf import FlaskForm
from wtforms import (fields,
                     validators)


class LDAPUserSearchForm(FlaskForm):
    username = fields.TextField('Username', validators=[validators.InputRequired()])
