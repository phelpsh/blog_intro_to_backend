import os
import jinja2
import webapp2
import re
import hashlib
import hmac
import random
import string
from google.appengine.ext import db
from models import User, Post, Like, Comment

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

    # def initialize(self, *a, **kw):
    #     # checks to see if cookie exists at the beginning of the session
    #     # called by App Engine
    #     webapp2.RequestHandler.initialize(self, *a, **kw)
    #     uid = self.read_secure_cookie('user')
    #     self.user = uid and User.by_id(int(uid))
    #     # not used

    def good_cookie_exists(self):
        h = self.request.cookies.get('user')  # cookie exists
        loggedin = self.read_secure_cookie('user')  # cookie is legit
        if h and loggedin:
            return True
        else:
            return False

    def user_owns_post(self, key):
        h = self.request.cookies.get('user')
        if not h == "":
            username = h.split("|")[0]
            p = db.get(key)
            if not p:
                return False
            else:
                if p.creator == username:
                    return True
        else:
            return False

    def user_owns_comment(self, key):
        h = self.request.cookies.get('user')
        if not h == "":
            username = h.split("|")[0]
            p = db.get(key)
            if not p:
                return False
            else:
                if p.user == username:
                    return True
        else:
            return False


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
# Display initial blog page
############################################


class MainPage(Handler):
    def render_front(self, creator):
        posts = Post.all().order('-created')
        # posts = db.GqlQuery("select * from Post order by created desc
        # limit 10")
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
            self.render('index.html', posts=posts, creator=creator,
                        userlikes=userlikes)
        else:
            self.render('noposts.html')

    def get(self):
        # check for proper cookie
        if self.good_cookie_exists():
            # check for user to pass to index.html
            # user is first part of cookie
            h = self.request.cookies.get('user')
            creator = h.split("|")[0]
            self.render_front(creator)
        else:
            self.redirect("/login")
            return

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
        if self.good_cookie_exists():
            self.redirect("/")
            return
        else:
            self.render_login()

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
                    return
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
        if self.good_cookie_exists():
            self.redirect("/")
            return
        else:
            self.render("signup.html")

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
            return


class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/signup')
            return


class LogoutPage(Handler):
    def get(self):
        self.logout()
        self.redirect('/login')
        return

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
        if self.good_cookie_exists():
            self.render("edit_post.html")
        else:
            self.redirect("/login")
            return

    def post(self):

        self.write(self.request.get("cancel"))

        if self.request.get("cancel"):
            self.redirect("/")
            return

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            if self.good_cookie_exists():
                h = self.request.cookies.get('user')
                creator = h.split("|")[0]
                # write to DB
                p = Post(subject=subject, content=content,
                         creator=creator)
                p.put()  # commit entry
                pid = p.key().id()
                self.redirect('/blog/%s' % str(pid))
                return
            else:
                self.redirect('/login')
                return
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

        if self.good_cookie_exists():
            # get user name from cookie
            h = self.request.cookies.get('user')
            user = h.split("|")[0]
            key = db.Key.from_path('Post', int(post_id))
            p = db.get(key)
            if not p:
                self.redirect("/")
                return
            subject = p.subject
            content = p.content
            creator = p.creator
            self.render("permalink.html", subject=subject, content=content,
                        creator=creator, user=user, post_id=post_id)
        else:
            self.render("signup.html")


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
        if self.good_cookie_exists():
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if not post:
                self.redirect("/")
                return
            else:
                if self.user_owns_post(key):
                    subject = post.subject
                    content = post.content
                    self.render("edit_post2.html", subject=subject,
                                content=content, post_id=post_id)
                else:
                    self.redirect("/")
                    return
        else:
            self.redirect("/login")
            return

    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            if self.good_cookie_exists():
                h = self.request.cookies.get('user')
                creator = h.split("|")[0]
                # write to DB...
                key = db.Key.from_path('Post', int(post_id))
                post = db.get(key)
                if not post:
                    self.redirect("/")
                    return
                else:
                    if self.user_owns_post(key):
                        post.subject = subject
                        post.content = content
                        post.creator = creator
                        post.put()
                        self.redirect('/blog/%s' % str(post_id))
                    else:
                        self.redirect("/")
            else:
                self.redirect("/login")
        else:
            error = "Please enter both subject and content"
            self.render("edit_post2.html", subject=subject, content=content,
                        error=error)


class DeletePostPage(Handler):
    def get(self, post_id):
        if self.good_cookie_exists():
            #  delete the post
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if not post:
                self.redirect("/login")
                return
            else:
                if self.user_owns_post(key):
                    post.delete()
                    self.render("success.html", deletedthing="post",
                                post_id=post_id, write_out=False)
                else:
                    self.redirect("/")
                    return
        else:
            self.redirect("/login")
            return


############################################
# End edit post
############################################

############################################
# Comments handlers - new, edit, display
############################################


class CommentPage(Handler):
    def get(self, post_id):
        if self.good_cookie_exists():
            # get user name from cookie
            h = self.request.cookies.get('user')
            curuser = h.split("|")[0]
            comments = Comment.all().filter('post_id =', post_id)

            # get post subject from Post table using post_id for
            # display at top of page
            key = db.Key.from_path('Post', int(post_id))
            p = db.get(key)
            if not p:
                self.redirect("/")
                return
            subject = p.subject
            self.render("comments.html", comments=comments, post_id=post_id,
                        curuser=curuser, subject=subject)
        else:
            self.redirect("/login")
            return


class NewCommentPage(Handler):
    def get(self, post_id):
        if self.good_cookie_exists():
            self.render("newcomment.html", post_id=post_id)
        else:
            self.redirect("/login")
            return

    def post(self, post_id):
        comment = self.request.get('comment')
        if comment:
            if self.good_cookie_exists():
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
                self.redirect("/login")
                return
        else:
            error = "Please enter text"
            self.render("newcomment.html", post_id=post_id,
                        error=error)


class EditCommentPage(Handler):
    def get(self, comment_id):
        if self.good_cookie_exists():
            # from DB, get info on that comment
            key = db.Key.from_path('Comment', int(comment_id))
            c = db.get(key)
            if not c:
                self.redirect("/")
                return
            else:
                if self.user_owns_comment(key):
                    comment = c.comment
                    self.render("editcomment.html", comment=comment,
                                comment_id=comment_id)
                else:
                    self.redirect("/")
                    return
        else:
            self.redirect("/login")
            return

    def post(self, comment_id):
        comment = self.request.get('comment')
        if comment:
            if self.good_cookie_exists():
                # write edits to DB...
                key = db.Key.from_path('Comment', int(comment_id))
                cm = db.get(key)
                if not cm:
                    self.redirect("/")
                    return
                else:
                    if self.user_owns_comment(key):
                        cm.comment = comment
                        # p = Post(subject=subject, content=content,
                        # creator=creator)
                        cm.put()
                        # go back to comments page for that post_id
                        # self.redirect('/comment/%s' % cm.post_id)
                        self.render("permacomment.html", comment=comment,
                                    post_id=cm.post_id)
                    else:
                        self.redirect("/")
                        return
            else:
                self.redirect("/login")
                return
        else:
            error = "Please enter text"
            self.render("editcomment.html", error=error)


class DeleteCommentPage(Handler):
    def get(self, comment_id):
        if self.good_cookie_exists():
            #  delete the comment
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)
            if not comment:
                self.redirect("/")
                return
            else:
                if self.user_owns_comment(key):
                    post_id = comment.post_id
                    svr = post_id  # have to double tap to ensure it stays...
                    comment.delete()  # somehow this deletes my post_id!!
                    self.render("success.html", deletedthing="comment",
                                post_id=svr, write_out=True)
                else:
                    self.redirect("/")
                    return
        else:
            self.redirect("/login")
            return


############################################
# End comments section
############################################

############################################
# Likes and unlikes
############################################


class LikePage(Handler):
    def get(self, post_id):
        if self.good_cookie_exists():
            #  put the user id and post_id into the Like entity
            #  go to success page, which will have link to home
            h = self.request.cookies.get('user')
            curusor = h.split("|")[0]
            # make sure user doesn't own post
            post_key = db.Key.from_path('Post', int(post_id))  # returning something, but what???
            if db.get(post_key) is not None:  # if post exists, continue
                owns = self.user_owns_post(post_key)
                if owns:  # if user owns the post, end
                    self.redirect("/")
                    return
                else:  # otherwise post exists and user is not owner
                    likes = Like.all().filter("post_id = ", str(post_id)).filter("user = ", curusor)  # NOQA
                    if likes.get() is not None:
                        # that user has already liked this post
                        self.redirect("/")  # UI blocks multiple liking as well
                        return
                    else:
                        # new Like entity
                        l = Like(post_id=post_id, user=curusor)
                        l.put()  # commit entry
                        self.render("successlike.html", loul="liked")
            else:
                self.redirect("/")
                return
        else:
            self.redirect("/login")
            return


class UnLikePage(Handler):
    def get(self, post_id):
        if self.good_cookie_exists():
            # delete that SPECIFIC like from DB
            # MUST match both user and post_id
            h = self.request.cookies.get('user')
            user = h.split("|")[0]
            post_id_s = str(post_id)
            # make sure current user doesn't own the post
            # user post_id to query Post
            post_key = db.Key.from_path('Post', int(post_id))
            if db.get(post_key) is not None:
                owns = self.user_owns_post(post_key)
                if owns:
                    self.redirect("/")
                    return
                else:
                    likes = Like.all().filter("user = ", user).filter("post_id = ", # NOQA
                                                                      post_id_s) # NOQA
                    key = likes.get().key()
                    key_go = db.get(key)
                    # verify the like exists
                    if not key_go:
                        self.redirect("/")
                        return
                    else:
                        key_go.delete()
                        self.render("successlike.html", loul="unliked")
            else:
                self.redirect("/")
                return
        else:
            self.redirect("/login")
            return


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
