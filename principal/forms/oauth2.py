from wtforms import Form
from wtforms import fields
from wtforms import validators
from wtforms import widgets
from wtforms.fields import html5

from flask_wtf import FlaskForm

class ListField(fields.Field):
    widget = widgets.TextInput()

    def _value(self):
        if self.data:
            return ', '.join(self.data)
        else:
            return ''

    def process_formdata(self, valuelist):
        data = []
        if valuelist:
            data = [tag.strip() for tag in valuelist[0].split(',') if len(tag.strip()) > 0]
        self.data = data
        

class URIListField(ListField):
    pass

class OAuth2ProjectForm(FlaskForm):
    name = fields.TextField('Name',
            validators=[validators.InputRequired(),
                        validators.Length(min=3)])
    description = fields.TextField('Description',
            validators=[validators.InputRequired()])

    redirect_uris = URIListField('Redirect URIs',
            validators=[# validators.URL(),
                        validators.InputRequired()])
    scopes = ListField('Allow Scopes',
            default=['email'],
            validators=[validators.InputRequired()])

