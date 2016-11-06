import json
import re
import time

import falcon
import peewee
from falcon_cors import CORS
from jose import jwt
from playhouse.shortcuts import model_to_dict

from config.secret import secret
from db.middleware import DBConnectMiddleware
from db.models import Episode, Podcast, User
from rss.rss import RSSWriter


# UTILITY METHODS #

# ~~~~~~~~~ HOOKS ~~~~~~~~~#

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

        # Is the token properly signed?
        decoded = jwt.decode(token, secret)

        # Is the user allowed to see this resource?
        user = decoded['sub']  # user_id
        if 'user_id' in params and user != params['user_id']:
            forbidden()
            # TODO: Also check if the user has access to this resource

            # Is the token expired?
            try:
                exp = decoded['exp']
                if time.gmtime(exp) < time.gmtime():  # if token is expired
                    raise falcon.HTTPUnauthorized('Authorization expired',
                                                  'Your auth token has expired.',
                                                  ['Token type="JWT"'])
            except (KeyError, TypeError):
                raise falcon.HTTPUnauthorized('Auth expiration required',
                                              'Your auth token does not contain a valid expiration time. '
                                              'Please request a new auth token.',
                                              ['Token type="JWT"'])

        params['user_id'] = user
    except (AttributeError, jwt.JWTError, KeyError):
        supply_valid_token()


# ~~~~~~~~~ OTHER UTILITY METHODS ~~~~~~~~~#

class BaseResource(object):
    def _get_from_db(self, obj, obj_id):
        o = obj.select().where(obj.id == obj_id)
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
            in_use = str(e).split('.')[-1].strip()  # hack to see which field is problematic
            raise falcon.HTTPConflict('{} in use'.format(in_use.title()),
                                      'The {} you provided is already in use.'.format(in_use))
        except Exception:
            obj_type = db_class.__name__.lower()
            raise falcon.HTTPInternalServerError('Error saving {}'.format(obj_type),
                                                 'There was an unknown error saving your '
                                                 'new {}. Please try again later.'.format(obj_type))

        res.body = json.dumps({'id': ident})


class BaseInfoResource(BaseResource):
    def _get(self, db_class, ident, *allowed_fields):
        obj = self._get_from_db(db_class, ident)

        if allowed_fields:
            r = model_to_dict(obj, recurse=False, only=allowed_fields)
        else:
            r = model_to_dict(obj, recurse=False, exclude=[db_class.created])

        return r

    def _put_obj(self, req, db_class, ident, *allowed_fields):
        allowed_fields_set = set()
        for f in allowed_fields:
            allowed_fields_set.add(f.name)

        obj = self._get_from_db(db_class, ident)

        j = self._parse_json(req)

        for field in j:
            if field in allowed_fields_set:
                setattr(obj, field, j[field])

        return obj

    def _delete(self, res, db_class, ident):
        obj = self._get_from_db(db_class, ident)
        obj.delete_instance()

        res.status = falcon.HTTP_200


# RESOURCES #

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
            'exp': time.time() + 3600 * 14  # expire in 2 weeks
        }
        token = jwt.encode(claims, secret, algorithm='HS256')

        res.body = json.dumps({'id': user.id, 'jwt': token})


# /user/{user_id}
class UserInfoResource(BaseInfoResource):
    def on_get(self, req, res, user_id):
        r = self._get(User, user_id, User.id, User.name)
        res.body = json.dumps(r)

    @falcon.before(authenticate)
    def on_put(self, req, res, user_id):
        user = self._put_obj(req, User, user_id, User.name, User.email, User.password)
        self._validate_password(user.password)
        updated = user.save()

    @falcon.before(authenticate)
    def on_delete(self, req, res, user_id):
        self._delete(res, User, user_id)


# /podcast/new
class PodcastRegistrationResource(BaseRegistrationResource):
    def on_post(self, req, res):
        j = self._validate_posted_json(req,
                                       link=True,
                                       title=True,
                                       description=True,
                                       image=False)
        self._register(res, j, Podcast)


# /podcast/{podcast_id}
class PodcastInfoResource(BaseInfoResource):
    def on_get(self, req, res, podcast_id, format_):
        podcast = self._get_from_db(Podcast, podcast_id)
        if format_.lower() == 'json':
            podcast = model_to_dict(podcast, backrefs=True, exclude=[Podcast.created, Episode.created])
            res.body = json.dumps(podcast)
        elif format_.lower() == 'rss' or format_.lower() == 'xml':
            rss = RSSWriter(podcast.title, podcast.link, podcast.description)
            if podcast.image:
                rss.add_to_channel('itunes:image', href=podcast.image)
            res.body = str(rss)
        else:
            raise falcon.HTTPInvalidParam('Specify "json" or "rss"',
                                          'format')

    @falcon.before(authenticate)
    def on_put(self, req, res, podcast_id):
        podcast = self._put_obj(req,
                                res,
                                Podcast,
                                podcast_id,
                                Podcast.link,
                                Podcast.title,
                                Podcast.description,
                                Podcast.image)
        podcast.save()

    @falcon.before(authenticate)
    def on_put(self, req, res, podcast_id):
        self._delete(res, Podcast, podcast_id)


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
app.add_route('/api/user/{user_id}', UserInfoResource())

# Podcast interactions
app.add_route('/api/podcast/new', PodcastRegistrationResource())
app.add_route('/api/podcast/{podcast_id}/{format_}', PodcastInfoResource())
# app.add_route('/api/podcast/review', PodcastReviewResource())
