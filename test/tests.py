import sys, os.path

from webtest import TestApp

sys.path.append(os.path.abspath(os.path.join(
	os.path.dirname(__file__),
	os.path.pardir,
	'src')))

from api import app
from models import User


# Verbs
TEST = 'Testing'
GET = 'Getting'
POST = 'Posting'
PUT = 'Putting'
DELETE = 'Deleting'

# Test user details
user_email = 'test@test.com'
user_name = 'Tester'
user_password = 'password1'
altuser_email = 'alt@test.com'
altuser_name = 'Alt'
altuser_password = user_password
user_name_edited = 'Edited'
user_email_edited = 'edited@edited.com'
user_password_edited = 'edited123'

def testing(url, verb=None):
	if verb is None:
		verb = TEST

	print('{} {}'.format(verb, url))

	return url

def standard_test(res):
	assert res.content_type == 'application/json'
	assert res.content_length > 0

def clear_user(email):
	user = User.select().where(User.email == email)
	if user.exists():
		user.get().delete_instance()


if __name__ == '__main__':

	app = TestApp(app)


	'''
	Start by clearing out the test data.
	With on delete cascade turned on, this should automatically clear
	   all testing data.
	'''
	clear_user(user_email)
	clear_user(altuser_email)
	clear_user(user_email_edited)


	### USER REGISTRATION ###
	url = testing('/api/user/register', POST)

	# (X) Missing name
	app.post_json(url, {"email": user_email,
		"password": user_password},
		status=400)

	# (X) Missing password
	app.post_json(url, {"email": user_email,
		"name": user_name},
		status=400)

	# (X) Missing email
	app.post_json(url, {"password": user_password,
		"name": user_name},
		status=400)

	# (X) Password is only letters
	app.post_json(url, {"email": user_email,
		"password": "password",
		"name": user_name},
		status=400)

	# (X) Password is less than 8 characters
	app.post_json(url, {"email": user_email,
		"password": "pass",
		"name": user_name},
		status=400)

	# (*) All login data correct
	res = app.post_json(url, {"email": user_email,
		"password": user_password,
		"name": user_name})
	userId = res.json['id']

	# (X) User already exists
	app.post_json(url, {"email": user_email,
		"password": user_password,
		"name": user_name},
		status=409)

	# (-) Create an alternate user for testing purposes
	res = app.post_json(url, {"email": altuser_email,
		"password": altuser_password,
		"name": altuser_name})
	altUserId = res.json['id']


	### USER LOGIN ###
	url = testing('/api/user/login', POST)

	# (*) Successful login
	res = app.post_json(url, {"email": user_email, "password": user_password})
	standard_test(res)

	# (*) User ID matches the one supplied at register
	assert res.json['id'] == userId

	# (*) Collect the auth token
	token = res.json['jwt']
	assert len(token) > 0
	auth = {'Authorization': 'Bearer {}'.format(token)}

	# (-) Collect the auth token for the alternate user
	res = app.post_json(url, {"email": altuser_email, "password": altuser_password})
	token = res.json['jwt']
	altAuth = {'Authorization': 'Bearer {}'.format(token)}

	# (X) User does not exist
	app.post_json(url,
		{"email": "wrong@nowhere.com", "password": user_password},
		status=401)
	
	# (X) Incorrect password for existing user
	app.post_json(url,
		{"email": user_email, "password": "wrongpassword"},
		status=401)


	### USER INFO ###
	url = testing('/api/user/{}'.format(userId), GET)

	# (*) Correct information
	res = app.get(url)
	standard_test(res)
	assert res.json['id'] == userId
	assert res.json['name'] == 'Tester'

	# (*) Auth token is correctly ignored, correct information
	res = app.get(url, headers=auth)
	standard_test(res)
	assert res.json['id'] == userId
	assert res.json['name'] == 'Tester'

	# (X) User does not exist
	url = testing('/api/user/{}'.format(5000), GET)
	res = app.get(url, status=404)
	url = testing('/api/user/{}'.format(-1), GET)
	res = app.get(url, status=404)

	# (*) Successfully edit user
	url = testing('/api/user/{}'.format(userId), PUT)
	res = app.put_json(url,
		{"name": user_name_edited,
		"email": user_email_edited,
		"password": user_password_edited},
		headers=auth)
	res = app.get('/api/user/{}'.format(userId)) # make sure name is changed but id isn't
	assert res.json['id'] == userId
	assert res.json['name'] == user_name_edited
	res = app.post_json('/api/user/login', # make sure new credentials work for login
		{"email": user_email_edited, "password": user_password_edited})
	assert res.json['id'] == userId
	res = app.post_json('/api/user/login',
		{"email": user_email_edited, "password": user_password},
		status=401)

	# (X) Unsuccessfully edit user, unauthorized
	app.put_json(url, {"name": user_name}, status=401)
	
	# (X) Unsuccessfully edit user, invalid password
	app.put_json(url, {"password": "abc"}, headers=auth, status=400)

	# (-) Revert user edits
	app.put_json(url,
		{"name": user_name,
		"email": user_email,
		"password": user_password},
		headers=auth)
