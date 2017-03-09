from google.appengine.ext import db


############################################
# Datastore models
############################################


class User(db.Model):
    """Sub model for representing a blog author."""
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)


class Post(db.Model):
    """Sub model for representing a blog posting."""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    creator = db.StringProperty(required=True)


class Comment(db.Model):
    post_id = db.StringProperty(required=True)
    comment = db.StringProperty(required=True)
    user = db.StringProperty(required=True)


class Like(db.Model):
    post_id = db.StringProperty(required=True)
    user = db.StringProperty(required=True)


############################################
# End datastore models
############################################