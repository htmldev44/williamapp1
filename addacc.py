from app import db, User, app
from werkzeug.security import generate_password_hash
import getpass

print('Create a new account')
first_name = input('First name: ')
profile_pic = input('Profile pic filename (in static folder): ')
role = input('Role (e.g., coder): ')
password = getpass.getpass('Password: ')
email = input('School email: ')
is_teacher = input('Is this a teacher account? (y/n): ').lower() == 'y'

with app.app_context():
	user = User(first_name=first_name, profile_pic=profile_pic, role=role, password_hash=generate_password_hash(password), email=email, is_teacher=is_teacher)
	db.session.add(user)
	db.session.commit()
print('Account created!')
