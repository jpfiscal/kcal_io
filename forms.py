from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, SelectField, DecimalField, IntegerField, FileField, HiddenField
from wtforms.validators import DataRequired, Email, Length, NumberRange, ValidationError, Optional
from flask_wtf.file import FileField, FileAllowed
from datetime import datetime

class LoginForm(FlaskForm):
    """Login Form"""

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[Length(min=6)])

class UserAddForm(FlaskForm):
    """Form for creating/registering new users."""

    username = StringField('Username', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Length(min=6)])
    password_retype = PasswordField('Re-enter Password', validators=[Length(min=6)])

    def validate_password_retype(self,field):
        if self.password.data != field.data:
            raise ValidationError('Passwords must match.')

class UserDetailsForm(FlaskForm):
    """Input User Details that aren't expected to change"""

    birthdate = DateField('Birth Date', validators=[DataRequired()])
    gender = SelectField('Gender', choices=['M', 'F'], validators=[DataRequired()])
    weight = DecimalField('Weight in Kg', places=2,rounding=None,use_locale=False, validators=[DataRequired()])
    height = DecimalField('Height in cm', places=2,rounding=None,use_locale=False, validators=[DataRequired()])
    fat_perc = DecimalField('Fat Percentage', places=2,rounding=None,use_locale=False, validators=[NumberRange(min=0, max=100, message = 'Value must be between 0%% and 100%%')])

class ManualMealInputForm(FlaskForm):
    """Form used to manually input user's meals"""

    meal_name = StringField('Meal Name', validators=[DataRequired()])
    meal_date = DateField('Date', validators=[DataRequired()], default=datetime.utcnow())
    meal_lbl = SelectField('Meal', choices=['Breakfast', 'Lunch', 'Dinner', 'Morning Snack', 'Afternoon Snack', 'Evening Snack'], validators=[DataRequired()])
    total_kcal = IntegerField('Total kCal in meal', validators=[DataRequired()])
    carbs = DecimalField('Carbs (g)', places=2, rounding=None, use_locale=False, validators=[Optional()])
    fat = DecimalField('Fat (g)', places=2, rounding=None, use_locale=False, validators=[Optional()])
    protein = DecimalField('Protein (g)', places=2, rounding=None, use_locale=False, validators=[Optional()])
    form_type = HiddenField(default='manual')

class MealPhotoForm(FlaskForm):
    """Form used to manually input user's meals"""
    meal_photo = FileField('Meal Photo', validators=[FileAllowed(['jpg','png','HEIC'], 'Images only'), DataRequired()])
    meal_date = DateField('Date', validators=[DataRequired()], default=datetime.utcnow())
    meal_lbl = SelectField('Meal', choices=['Breakfast', 'Lunch', 'Dinner', 'Morning Snack', 'Afternoon Snack', 'Evening Snack'], validators=[DataRequired()])
    form_type = HiddenField(default='photo')

class EditMealEstimateForm(FlaskForm):
    """Once GPT4 returns the kcal and macronutrient estiamte, users can edit the returned data"""

    meal_name = StringField('Meal Name', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()], default=datetime.utcnow())
    # weight = DecimalField('Weight (in grams)', places=2, rounding=None, use_locale=False, validators=[DataRequired()])
    total_kcal = IntegerField('Total kCal in meal', places=2, rounding=None, use_locale=False, validators=[DataRequired()])
    carbs = DecimalField('Carbs (g)', places=2, rounding=None, use_locale=False)
    fat = DecimalField('Fat (g)', places=2, rounding=None, use_locale=False)
    protein = DecimalField('Protein (g)', places=2, rounding=None, use_locale=False)

class ManualActivityInputForm(FlaskForm):
    activity_nm = SelectField('Exercise Name', validators=[DataRequired()])
    activity_date = DateField('Date', validators=[DataRequired()], default=datetime.utcnow())
    duration = DecimalField('Exercise Duration (mins)', places=2, rounding=None, use_locale=False, validators=[NumberRange(min=0, message = 'Cannot be a negative number')])
    kcal_out = DecimalField('Kcals Burnt', places=2, rounding=None, use_locale=False, validators=[NumberRange(min=0, message = 'Cannot be a negative number')])

class BodyWeightForm(FlaskForm):
    weight = DecimalField('Weight in Kg', places=2,rounding=None,use_locale=False, validators=[DataRequired()])
    fat_perc = DecimalField('Fat Percentage', places=2,rounding=None,use_locale=False, validators=[NumberRange(min=0, max=100, message = 'Value must be between 0%% and 100%%')])
    weigh_in_date = DateField('Birth Date', validators=[DataRequired()], default=datetime.utcnow())