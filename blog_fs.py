import os
import jinja2
import webapp2
import re
import datetime
import hashlib
import hmac
import random
import string
from string import letters
from google.appengine.ext import db


############################################
# Set-up and housekeeping
############################################

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        # error checks for empty cookies
        if not cookie_val == "":
            return cookie_val and check_secure_val(cookie_val)
        else:
            return None

    def login(self, user):
        self.set_secure_cookie('user', user)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')

    def initialize(self, *a, **kw):
        # checks to see if cookie exists at the beginning of the session
        # called by App Engine
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


############################################
# End set-up and housekeeping
############################################

############################################
# Authentication section
# (taken from class examples)
############################################

SECRET = "SECRET_FOR_HASH"  # shouldn't be stored here


def hash_str(s):
    # return hashlib.sha256(s).hexdigest()
    return hmac.new(SECRET, s).hexdigest()
    # for hashing cookies


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))  # use pipe vice comma


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    # returns 5 random letters for salting
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)
    # for hashing passwords - what's returned gets stored


def valid_pw(name, password, h):
    # to check a password is valid
    salt = h.split(',')[1]
    return h == make_pw_hash(name, password, salt)  # returns true if match


def users_key(group='default'):
    return db.Key.from_path('users', group)


############################################
# End authentication
############################################

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

############################################
# Display initial blog page
############################################


class MainPage(Handler):
    def render_front(self, creator):

        posts = Post.all().order('-created')
        # posts = db.GqlQuery("select * from Post order by created desc limit 10")
        # look for likes in Like entity for the current user (creator)
        likes = Like.all().filter("user = ", creator)
        dict = []
        if likes:
            # iterate through and make dictionary from response
            for l in likes:
                dict.append(int(l.post_id))
        # turn dict into a set
        userlikes = set(dict)
        if posts:
            self.render('index.html', posts=posts, creator=creator, userlikes=userlikes)
        else:
            self.render('noposts.html')

    def get(self):
        # check for proper cookie
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.redirect("/login")
        else:
            # check for user to pass to index.html
            # user is first part of cookie
            h = self.request.cookies.get('user')
            creator = h.split("|")[0]
            self.render_front(creator)

############################################
# End display initial blog page
############################################

############################################
# Built-in user validations
# (taken from lecture notes)
############################################

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

############################################
# End built-in user validations
############################################

############################################
# Initial pages handling: login and signup
############################################


class LoginPage(Handler):
    def render_login(self, name="", password="", error=""):
        self.render("login.html", name=name, password=password, error=error)

    def get(self):
        # check for proper cookie
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render_login()
        else:
            self.redirect("/")
        # the below works alone
        # self.render_login()

    def post(self):
        name = self.request.get("name")
        password = self.request.get("password")
        if name and password:
            # check against User database to make sure it's all valid
            username = User.all().filter("username = ", name).get()
            if username:
                if valid_pw(name, password, username.password):
                    # passwords match, set cookie
                    self.set_secure_cookie(str('user'), str(name))
                    # redirect to home page
                    self.redirect("/")
                else:
                    error = "Invalid user name or password"
                    self.render_login(name=name, error=error)
            else:
                error = "Sorry. I don't recognize that username/password."
                self.render_login(name, password, error)
        else:
            error = "Both username and password require input"
            self.render_login(name, password, error)


class Signup(Handler):
    def get(self):
        # check for cookie
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            # self.logout()  # clear cookie if one exits
            self.render("signup.html")
        else:
            self.redirect("/")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # check to see if username is already in use
        result = User.all().filter("username = ", username).get()

        if result is not None:
            params['error_username'] = "That username is already in use."
            have_error = True
        # end existing username check

        if have_error:
            self.render('signup.html', **params)
        else:
            # write to DB with hashed pwd
            password_h = make_pw_hash(name=username, pw=password)
            u = User(username=username, password=password_h,
                     email=email)
            # create a new DB entry
            u.put()
            # now create a cookie for the new user
            self.set_secure_cookie(str('user'), str(username))
            self.redirect('/welcome?username=' + username)


class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/signup')


class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/login')

############################################
# End initial pages handling: login and signup
############################################


############################################
# Blog page information and handling
############################################

# def blog_key(name='default'):
#     return db.Key.from_path('blogs', name)  # what is 'blogs'???


class NewPost(Handler):
    def get(self):
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            # self.logout()  # clear cookie if one exits
            self.render("signup.html")
        else:
            self.render("edit_post.html")

    def post(self):

        self.write(self.request.get("cancel"))

        if self.request.get("cancel"):
            self.redirect("/")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # get user name from cookie
            h = self.request.cookies.get('user')
            creator = h.split("|")[0]
            # write to DB...
            p = Post(subject=subject, content=content,
                     creator=creator)
            p.put()  # commit entry
            pid = p.key().id()
            self.redirect('/blog/%s' % str(pid))
        else:
            error = "Please enter both a subject and content."
            self.render("edit_post.html", subject=subject, content=content,
                        error=error)


############################################
# End blog page information and handling
############################################

############################################
# Single post page
############################################

class PostPage(Handler):
    def get(self, post_id):

        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("signup.html")
        else:
            # get user name from cookie
            h = self.request.cookies.get('user')
            user = h.split("|")[0]
            key = db.Key.from_path('Post', int(post_id))
            p = db.get(key)
            # needs error checking; goes to blank screen if no p
            if not p:
                self.error(404)
                return
            subject = p.subject
            content = p.content
            creator = p.creator
            self.render("permalink.html", subject=subject, content=content,
                        creator=creator, user=user, post_id=post_id)


############################################
# End single post page
############################################

############################################
# Test to see user is written
############################################

class TestPage(Handler):
    def render_front(self):
        users = db.GqlQuery("select * from User")
        if users:
            self.render('TEST_user.html', users=users)
        else:
            self.write('no users')

    def get(self):
        self.render_front()

############################################
# End test to see user is written
############################################

############################################
# Edit Post
############################################


class EditExisting(Handler):
    def get(self, post_id):
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("signup.html")
        else:
            # make sure user is right?
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if post:
                subject = post.subject
                content = post.content
            self.render("edit_post2.html", subject=subject, content=content,
                        post_id=post_id)

    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            # get user name from cookie
            h = self.request.cookies.get('user')
            creator = h.split("|")[0]
            # write to DB...
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.creator = creator
            # p = Post(subject=subject, content=content, creator=creator)
            post.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "Please enter both a subject and content for your "
            "blog entry."
            self.render("edit_post2.html", subject=subject, content=content,
                        error=error)


class DeletePostPage(Handler):
    def get(self, post_id):
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("login.html")
        else:
            #  delete the post
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            post.delete(deadline=2)
            self.redirect("/")

############################################
# End edit post
############################################

############################################
# Comments handlers - new, edit, display
############################################


class CommentPage(Handler):
    def get(self, post_id):
        # check to see if valid cookie
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("signup.html")
        else:
            # get user name from cookie
            h = self.request.cookies.get('user')
            curuser = h.split("|")[0]
            comments = Comment.all().filter('post_id =', post_id)

            # get post subject from Post table using post_id for
            # display at top of page
            key = db.Key.from_path('Post', int(post_id))
            p = db.get(key)
            subject = p.subject
            self.render("comments.html", comments=comments, post_id=post_id,
                        curuser=curuser, subject=subject)


class NewCommentPage(Handler):
    def get(self, post_id):
        # check to see if valid cookie
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("signup.html")
        else:
            self.render("newcomment.html", post_id=post_id)

    def post(self, post_id):
        comment = self.request.get('comment')
        if comment:
            # get user name from cookie
            h = self.request.cookies.get('user')
            creator = h.split("|")[0]
            # write new comment to DB...
            c = Comment(post_id=post_id, comment=comment, user=creator)
            c.put()  # commit entry
            # go back to comments page for that post_id
            # self.redirect('/comment/%s' % post_id) # not showing new data
            self.render("permacomment.html", comment=comment,
                        post_id=post_id)
        else:
            error = "Please enter text"
            self.render("newcomment.html", post_id=post_id,
                        error=error)


class EditCommentPage(Handler):
    def get(self, comment_id):
        # check to see if valid cookie
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("signup.html")
        else:
            # from DB, get info on that comment
            key = db.Key.from_path('Comment', int(comment_id))
            c = db.get(key)
            if c:
                comment = c.comment
                self.render("editcomment.html", comment=comment,
                            comment_id=comment_id)
            else:
                self.redirect("/")

    def post(self, comment_id):
        comment = self.request.get('comment')
        if comment:
            # write edits to DB...
            key = db.Key.from_path('Comment', int(comment_id))
            cm = db.get(key)
            cm.comment = comment
            # p = Post(subject=subject, content=content, creator=creator)
            cm.put()
            # go back to comments page for that post_id
            # self.redirect('/comment/%s' % cm.post_id)
            self.render("permacomment.html", comment=comment,
                        post_id=cm.post_id)
        else:
            error = "Please enter text"
            self.render("editcomment.html", error=error)


class DeleteCommentPage(Handler):
    def get(self, comment_id):
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("login.html")
        else:
            #  delete the comment
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            post_id = comment.post_id
            svr = post_id  # have to double tap to ensure it stays...
            comment.delete()  # somehow this deletes my post_id!!
            # self.redirect("/")
            self.render("success.html", deletedthing="comment", post_id=svr)
            # back to comments list success


############################################
# End comments section
############################################

############################################
# Likes and unlikes
############################################


class LikePage(Handler):
    def get(self, post_id):
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("login.html")
        else:
            #  put the user id and post_id into the Like entity
            #  go to success page, which will have link to home
            h = self.request.cookies.get('user')
            curusor = h.split("|")[0]
            # new Like entity
            l = Like(post_id=post_id, user=curusor)
            l.put()  # commit entry
            self.render("successlike.html", loul="liked")


class UnLikePage(Handler):
    def get(self, post_id):
        loggedin = self.read_secure_cookie('user')
        if loggedin is None:
            self.render("login.html")
        else:
            # delete that SPECIFIC like from DB
            # MUST match both user and post_id
            h = self.request.cookies.get('user')
            user = h.split("|")[0]
            post_id = str(post_id)
            likes = Like.all().filter("user = ", user).filter("post_id = ", post_id)
            key = likes.get().key()
            key_go = db.get(key)
            key_go.delete()
            self.render("successlike.html", loul="unliked")
            
            # back to comments list success

############################################
# End of likes and unlikes
############################################

############################################
# Information for handling and redirects
############################################


app = webapp2.WSGIApplication([('/', MainPage),
                              ('/login', LoginPage),
                              ('/logout', LogoutPage),
                              ('/signup', Signup),
                              ('/welcome', Welcome),
                              ('/like/([0-9]+)', LikePage),
                              ('/unlike/([0-9]+)', UnLikePage),
                              ('/edit', NewPost),
                              ('/blog/([0-9]+)', PostPage),
                              ('/comment/([0-9]+)', CommentPage),
                              ('/editcomment/([0-9]+)', EditCommentPage),
                              ('/newcomment/([0-9]+)', NewCommentPage),
                              ('/test', TestPage),
                              ('/deletepost/([0-9]+)', DeletePostPage),
                              ('/deletecomment/([0-9]+)', DeleteCommentPage),
                              ('/editpost/([0-9]+)', EditExisting),
                               ],
                              debug=True)
