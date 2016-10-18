import sys, os.path

from webtest import TestApp

sys.path.append(os.path.abspath(os.path.join(
	os.path.dirname(__file__),
	os.path.pardir,
	'src')))

from api import app
from models import User


TEST = 'Testing'
GET = 'Getting'
POST = 'Posting'
PUT = 'Putting'
DELETE = 'Deleting'

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
	clear_user('test@test.com')
	clear_user('alt@test.com')


	### USER REGISTRATION ###
	url = testing('/api/user/register', POST)

	# (X) Missing name
	app.post_json(url, {"email": "test@test.com",
		"password": "password1"},
		status=400)

	# (X) Missing password
	app.post_json(url, {"email": "test@test.com",
		"name": "Tester"},
		status=400)

	# (X) Missing email
	app.post_json(url, {"password": "password1",
		"name": "Tester"},
		status=400)

	# (X) Password is only letters
	app.post_json(url, {"email": "test@test.com",
		"password": "password",
		"name": "Tester"},
		status=400)

	# (X) Password is less than 8 characters
	app.post_json(url, {"email": "test@test.com",
		"password": "pass",
		"name": "Tester"},
		status=400)

	# (*) All login data correct
	res = app.post_json(url, {"email": "test@test.com",
		"password": "password1",
		"name": "Tester"})
	userId = res.json['id']

	# (X) User already exists
	app.post_json(url, {"email": "test@test.com",
		"password": "password1",
		"name": "Tester"},
		status=409)

	# (-) Create an alternate user for testing purposes
	res = app.post_json(url, {"email": "alt@test.com",
		"password": "password1",
		"name": "Alt"})
	altUserId = res.json['id']


	### USER LOGIN ###
	url = testing('/api/user/login', POST)

	# (*) Successful login
	res = app.post_json(url, {"email": "test@test.com", "password": "password1"})
	standard_test(res)
	assert res.json['id'] == userId

	# (*) Collect the auth token
	token = res.json['jwt']
	assert len(token) > 0
	auth = {'Authorization': 'Bearer {}'.format(token)}

	# (-) Collect the auth token for the alternate user
	res = app.post_json(url, {"email": "alt@test.com", "password": "password1"})
	token = res.json['jwt']
	altAuth = {'Authorization': 'Bearer {}'.format(token)}

	# (X) User does not exist
	app.post_json(url,
		{"email": "wrong@nowhere.com", "password": "password1"},
		status=401)
	
	# (X) Incorrect password for existing user
	app.post_json(url,
		{"email": "test@test.com", "password": "wrongpassword"},
		status=401)
