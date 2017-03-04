import webapp2
import jinja2
from string import letters
import random
import hashlib
import hmac
import os

template_dir = os.path.join(os.path.dirname(__file__))
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = "iamnosecret"

def make_secure_val(s):
  return "%s|%s" % (s, hmac.new(secret, s).hexdigest())

def check_secure_val(s):
    val=s.split('|')[0]
    if s==make_secure_val(val):
        return val

#Generate Salt - random character string

def make_salt(length=5):
  return ''.join(random.choice(letters) for i in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, pw, h):
    salt=h.split(',')[1]
    return h ==make_pw_hash(name,pw,salt)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_str(self, template, **params):
        params['user'] = self.user
        t=jinja_env.get_template(template)
        return t.render(params)

    # def login(self, user):
    #     self.set_secure_cookie('user_id', str(user.key().id()))

    #Makes cookie value secure and sets the secure cookie
    def set_secure_cookie(self,name,val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    #Reads the cookie for name, and returns the secure value, if the cookie exists and passes the security check
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    #check if the user is logged in and set the current user to that
    # def initialize(self, *a, **kw):
    #     webapp2.RequestHandler.initialize(self, *a, **kw)
    #     uid = self.read_secure_cookie('user_id')
    #     self.user = uid and User.by_id(int(uid))
