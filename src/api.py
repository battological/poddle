import falcon
import json
import peewee
import pprint
import re
import time

from datetime import datetime
from falcon_cors import CORS
from jose import jwt

from models import User, Podcast, Episode, PodcastInteract, EpisodeInteract, db
from secret import secret


########## UTILITY METHODS ##########

#~~~~~~~~~ HOOKS ~~~~~~~~~#

# Authenticate requests (for requests that require it)
def authenticate(req, res, resource, params):
	def supply_valid_token():
		raise falcon.HTTPUnauthorized('Auth token required',
			'Please provide a valid auth token in the request\'s '
			'Authorization header.',
			['Token type="JWT"'])

	def forbidden():
		raise falcon.HTTPForbidden('Permission denied',
			'You are not authorized to perform this action. '
			'This resource does not seem to belong to you.')

	try:
		token = req.auth.replace('Bearer ', '').strip()
	except:
		supply_valid_token()

	# Is the token properly signed?
	try:
		decoded = jwt.decode(token, secret)
	except jwt.JWTError:
		supply_valid_token()

	# Is the user allowed to see this resource?
	try:
		user = decoded['sub'] # userId
		if 'userId' in params and user != params['userId']:
			forbidden()
		# TODO: Also check if the user has access to this resource

	except KeyError:
		supply_valid_token()

	# Is the token expired?
	try:
		exp = decoded['exp']
		if time.gmtime(exp) < time.gmtime(): # if token is expired
			raise falcon.HTTPUnauthorized('Authorization expired',
				'Your auth token has expired.',
				['Token type="JWT"'])
	except (KeyError, TypeError):
		raise falcon.HTTPUnauthorized('Auth expiration required',
			'Your auth token does not contain a valid expiration time. '
			'Please request a new auth token.',
			['Token type="JWT"'])

	params['userId'] = user


#~~~~~~~~~ OTHER UTILITY METHODS ~~~~~~~~~#

class BaseResource(object):

	def _get_from_db(self, obj, objId):
		o = obj.select().where(obj.id == objId)
		if not o.exists():
			raise falcon.HTTPNotFound()
		return o.get()
		

	def _parse_json(self, req):
		try:
			return json.loads(req.stream.read())
		except ValueError:
			raise falcon.HTTPBadRequest('JSON decode error',
				'The supplied JSON could not be decoded. '
				'Please supply valid JSON.')
			

	def _validate_password(self, password):
		if len(password) < 8 or len(re.sub('[A-Za-z]', '', password)) == 0:
			raise falcon.HTTPBadRequest('Invalid password',
				'Your password must be at least 8 characters '
				'and contain at least 1 number or symbol.')


	def _validate_posted_json(self, req, **kwargs):
		j = self._parse_json(req)

		if kwargs is not None:
			for field, required in kwargs.iteritems():
				if field not in j or len(j[field].strip()) == 0:
					if required:
						raise falcon.HTTPBadRequest('JSON missing {}.'.format(field),
							'The supplied JSON did not include a required "{}" field. '
							'Please supply a "{}" field.'.format(field, field))
					j[field] = None

		return j


class BaseRegistrationResource(BaseResource):

	def _register(self, res, json_req, db_class):
		try:
			ident = db_class.create(**json_req).id
		except peewee.IntegrityError as e:
			in_use = str(e).split('.')[-1].strip() # hack to see which field is problematic
			raise falcon.HTTPConflict('{} in use'.format(in_use.title()),
				'The {} you provided is already in use.'.format(in_use))
		except Exception:
			obj_type = db_class.__name__.lower()
			raise falcon.HTTPInternalServerError('Error saving {}'.format(obj_type),
				'There was an unknown error saving your '
				'new {}. Please try again later.'.format(obj_type))
		res.body = json.dumps({'id': ident})



########## MIDDLEWARE ##########

# Ensure database connection is opened and closed for each request
class DBConnectMiddleware(object):

	def process_request(self, req, res):
		db.connect()

	def process_response(self, req, res, resource):
		if not db.is_closed():
			db.close()


########## RESOURCES ##########

# /user/register
class UserRegistrationResource(BaseRegistrationResource):

	def on_post(self, req, res):
		j = self._validate_posted_json(req, email=True, password=True, name=True)
		self._validate_password(j['password'])
		self._register(res, j, User)

		
# /user/login
class UserResource(BaseResource):

	def on_post(self, req, res):
		j = self._parse_json(req)

		def invalid():
			raise falcon.HTTPUnauthorized('Invalid credentials',
				'Your login credentials are not correct. '
				'Please try again.',
				['Auth type="Password"'])

		try:
			email = j['email']
			password = j['password']
		except KeyError:
			raise falcon.HTTPUnauthorized('Invalid credentials',
				'Your email and/or password was not sent correctly. '
				'Please try again.',
				['Auth type="Password"'])

		user = User.select().where(User.email == email)

		if not user.exists():
			invalid()

		user = user.get()
		if not user.password.check_password(password.encode('utf-8')):
			invalid()

		claims = {
			'iss': 'http://poddle.com',
			'sub': str(user.id),
			'exp': time.time() + 3600 * 14 # expire in 2 weeks
		}
		token = jwt.encode(claims, secret, algorithm='HS256')

		res.body = json.dumps({'id': user.id, 'jwt': token})


# /user/{userId}
class UserInfoResource(BaseResource):

	def on_get(self, req, res, userId):
		user = self._get_from_db(User, userId)

		r = {'id': user.id, 'name': user.name}

		res.body = json.dumps(r)

	@falcon.before(authenticate)
	def on_put(self, req, res, userId):
		user  = self._get_from_db(User, userId)

		j = self._parse_json(req)

		if 'name' in j:
			user.name = j['name']
		if 'email' in j:
			user.email = j['email']
		if 'password' in j:
			user.password = j['password']
			self._validate_password(user.password)

		updated = user.save()
		

	@falcon.before(authenticate)
	def on_delete(self, req, res, userId):
		user = self._get_from_db(User, userId)
		user.delete_instance()
		
		res.status = falcon.HTTP_200


# /podcast/new
class PodcastRegistrationResource(BaseRegistrationResource):

	def on_post(self, req, res):
		j = self._validate_posted_json(req,
			link=True,
			title=True,
			description=True,
			image=False)
		self._register(res, j, Podcast)


# /podcast/{podcastId}
class PodcastInfoResource(BaseResource):

	def on_get(self, req, res, podcastId):
		podcast = self._get_from_db(Podcast, podcastId)

		r = {'link': podcast.link,
			'title': podcast.title, 
			'description': podcast.description}
		if podcast.image:
			r['image'] = podcast.image

		res.body = json.dumps(r)
		

# Add routes
cors = CORS(allow_all_origins=True,
        allow_all_methods=True,
        allow_headers_list=['Content-Type', 'Authorization'])

app = falcon.API(middleware=[
        cors.middleware,
	DBConnectMiddleware()
])

# User interactions
app.add_route('/api/user/register', UserRegistrationResource())
app.add_route('/api/user/login', UserResource())
app.add_route('/api/user/{userId}', UserInfoResource())

# Podcast interactions
app.add_route('/api/podcast/new', PodcastRegistrationResource())
app.add_route('/api/podcast/{podcastId}', PodcastInfoResource())
#app.add_route('/api/podcast/review', PodcastReviewResource())
