import os
import hashlib
import string
import random
import webapp2
import cgi
import jinja2
import hmac
import re

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                              autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def validUsername(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def validPassword(password):
	return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def ValidEmail(email):
	return not email or EMAIL_RE.match(email)

def hash_str(s):
	return hashlib.sha256(s).hexdigest()

def make_secure_val(s):
	return '%s|%s' % (s, hash_str(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def checkUserExists(username):
	q = db.GqlQuery("SELECT * FROM User WHERE username = :1" , make_secure_val(username))
	for x in q:
		return username == check_secure_val(x.username)

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(Handler):

	def get(self):
		self.render('signUp.html')

	def post(self):
		haveError = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		outParams = dict(username = username, email = email)

		if checkUserExists(username):
			outParams['error_username'] = "User exists"
			haveError = True
		elif not validUsername(username):
			outParams['error_username'] = "Invalid username"
			haveError = True

		if not validPassword(password):
			outParams['error_password'] = "Invalid password"
			haveError = True
		elif password != verify:
			outParams['error_verify'] = "The passwords dont match"
			haveError = True

		if not ValidEmail(email):
			outParams['error_email'] = "Invalid email"
			haveError = True 

		if haveError:
			self.render('signUp.html', **outParams)
		else:
			u = User(username = make_secure_val(username), password = make_secure_val(password), email = email)
			u_key = u.put()
			self.response.headers.add_header('Set-Cookie', 'user_id = %s; Path = /' % make_secure_val(str(u_key.id())))
			self.redirect("/welcome")

class Welcome(Handler):
	def get(self):
		HASH = self.request.cookies.get('user_id')
		if not check_secure_val(HASH):
			self.redirect('/signup')
		else:
			user_id = HASH.split('|')[0]
			username_HASH = User.get_by_id(int(user_id))
			username = username_HASH.username.split('|')[0]
			self.render("welcome.html", username = username)
		
class LoginPage(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		q = db.GqlQuery("SELECT * FROM User WHERE username = :1 AND password = :2", make_secure_val(username), make_secure_val(password))
		q_key = db.GqlQuery("SELECT __key__ FROM User WHERE username = :1 AND password = :2", make_secure_val(username), make_secure_val(password))
		key = q_key.get()
		for i in q:
			if username == check_secure_val(i.username) and password == check_secure_val(i.password):
				self.response.headers.add_header('Set-Cookie', 'user_id = %s; Path = /' % make_secure_val(str(key.id())))
				self.redirect('/welcome')

class LogoutPage(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id = ; Path = /')
		self.redirect('/signup')


app = webapp2.WSGIApplication([('/signup', MainPage), ('/welcome', Welcome), ('/login', LoginPage), ('/logout', LogoutPage)], debug = True)