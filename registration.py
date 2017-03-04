import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__))
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
#Secret - Random string, normally not stored in the code.
#Generlly stored in a module that's only on the production machine.
secret = "iamnosecret"

# Global render_str function that gets the template from the jinja environment and returns the rendered string from the template.
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Takes a string as an input and returns the secured value, using secret string and HMAC.
def make_secure_val(s):
  return "%s|%s" % (s, hmac.new(secret, s).hexdigest())

# Takes a string that contains the hash as input. Splits it into two.
#Uses the make_secure_val function to check if the secured value of the string matches the value in the hash.
def check_secure_val(s):
    val=s.split('|')[0]
    if s==make_secure_val(val):
        return val

# Main BlogHandler class
class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    #Makes cookie value secure and sets the secure cookie
    def set_secure_cookie(self,name,val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    #Reads the cookie for name, and returns the secure value, if the cookie exists and passes the security check
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # check if the user is logged in and set the current user to that
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    # Set the secure cookie for user login
    def login(self,user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Clear the user_id cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
#Generate Salt - a random character string
def make_salt(length=5):
  return ''.join(random.choice(letters) for i in xrange(length))

# Generats the password hash using sha256 and returns salt and hash value of passwrd.
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Checks if the password is valid by comparing the hashed values
def valid_pw(name, pw, h):
    salt=h.split(',')[1]
    return h == make_pw_hash(name,pw,salt)

# TODO: figure this out
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls,uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        # q = db.GqlQuery("SELECT * FROM User WHERE name= :uname", uname=name)
        # return q.get()
        u = User.all().filter('name = ', name).get()
        return u

    @classmethod # This classmethod is also used as a constructor instead of __init__
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    # Check if user name and password combination is valid and return the user object
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name) # Find the user by name
        if u and valid_pw(name, pw, u.pw_hash): # Check for user id and password combination is valid
            return u

#check valid username, password, and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    #each subclass of Signup an override this method. If the override is not implemented, the error occurs.
    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    #Register overrides done, and adds user details to db.
    def done(self):
        #Error occurs if the user name already exists.
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # Check if username and password combination is correct
        # Set the cookie for user_id
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg='Invalid Login %s' % u
            self.render('login.html', error=msg)

class Logout(BlogHandler):
    def get(self):
        self.logout() # Clear cookies on logout
        self.redirect('/login')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/signup', Register),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/logout', Logout)],
                              debug=True)
def main():
    app.run()