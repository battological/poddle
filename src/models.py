import os.path
from datetime import datetime
from peewee import *
from playhouse.fields import PasswordField


db_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
	os.path.pardir,
	'poddle.db'))
db = SqliteDatabase(db_path, pragmas=[('foreign_keys', 'ON')])

class BaseModel(Model):
	created = DateTimeField(default=datetime.now)
	class Meta:
		database=db

class User(BaseModel):
	email=CharField(unique=True)
	name=CharField()
	password=PasswordField()

class PodBase(BaseModel):
	link=CharField(unique=True)
	title=CharField()
	description=TextField()

class Podcast(PodBase):
	image=CharField(null=True)

class Episode(PodBase):
	podcast=ForeignKeyField(Podcast, related_name='episodes')
	audio=CharField()
	guid=CharField()
	published=DateTimeField()

class InteractBase(BaseModel):
	review=TextField(null=True)
	rating=IntegerField()

class EpisodeInteract(InteractBase):
	episode=ForeignKeyField(Episode, related_name='interacts')

class PodcastInteract(InteractBase):
	podcast=ForeignKeyField(Podcast, related_name='interacts')


def create_tables():
	db.connect()
	db.create_tables([User,
		Podcast,
		Episode,
		EpisodeInteract,
		PodcastInteract])
