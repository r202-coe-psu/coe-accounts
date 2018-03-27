from flask_wtf import FlaskForm
from wtforms import (fields,
                     validators)


class UserSearchForm(FlaskForm):
    username = fields.TextField('Username', validators=[validators.InputRequired()])
