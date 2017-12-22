#coding:utf-8
import tornado.ioloop
import tornado.web
import tornado.gen
import tornado.httpclient
import urllib,urlparse,base64,functools,re,json

config = {
  'CAS_SERVER_HOST':'https://test.open.changyan.com',
  'CAS_SERVER_ROUTE':'/sso/login',
  'CAS_LOGOUT_ROUTE':'/sso/logout',
  'CAS_VALIDATE_ROUTE':'/sso/v1/validation',
  'CAS_LOGIN_URL':"https://test.pass.changyan.com/login",
  'CAS_AFTER_LOGIN':"http://test.webtools.changyan.cn:5000",
  'CAS_AFTER_LOGOUT':"http://test.webtools.changyan.cn:5000"
}

def EduSSORequire(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.current_user:
            if self.request.method in ("GET", "HEAD"):
              if not self.request.path == "/":
                self.set_secure_cookie("cookie_rdst",urlparse.urljoin(self.request.protocol + "://" + self.request.host,self.request.path))
              url = self.get_login_url()
              if self.request.query:
                url += '?' + self.request.query
              self.redirect(url)
              return
            raise HTTPError(403)
        return method(self, *args, **kwargs)
    return wrapper

class BaseHandler(tornado.web.RequestHandler):
  def get_current_user(self):
    _usr_sso_openId = self.get_secure_cookie('_usr_sso_openId')
    return _usr_sso_openId
  def get_after_login_url(self):
    cookie_rdst = self.get_secure_cookie("cookie_rdst")
    if not cookie_rdst:
      cookie_rdst = config['CAS_AFTER_LOGIN']
    return cookie_rdst
class EduSSOLoginHandler(BaseHandler):
  @tornado.gen.coroutine
  def get(self):
    if self.request.arguments.has_key("ticket"):
      ticket = self.get_argument('ticket')
      validateUrl = urlparse.urljoin(config['CAS_SERVER_HOST'],config['CAS_VALIDATE_ROUTE'])
      callback = '_callback'
      params = {
        'service':self.get_after_login_url(),
        'ticket':ticket,
        'callback':callback
      }
      req = tornado.httpclient.HTTPRequest(validateUrl + "?" + urllib.urlencode(params))
      resp = yield tornado.gen.Task(tornado.httpclient.AsyncHTTPClient().fetch,req)
      callbackRet = resp.body
      p = re.compile( callback + "\((.*)\)")
      m = p.match(callbackRet)
      validRet = json.loads(m.group(1))
      isValid = True if validRet.get("code",0) else False
      if isValid:
        _usr_sso_openId = validRet['data']["openId"]
        _usr_attributes = validRet['data']["attributes"]
        self.set_secure_cookie('_usr_sso_openId',_usr_sso_openId)
        self.set_secure_cookie('_usr_attributes',json.dumps(_usr_attributes))
      else:
        self.clear_all_cookies()
      self.redirect(self.get_after_login_url())
    else:
      if not self.get_secure_cookie('rdst'):
        self.set_secure_cookie('rdst','cas_login_redirect')
        redirectUrl = urlparse.urljoin(config['CAS_SERVER_HOST'],config['CAS_SERVER_ROUTE'])
        params = {
          'service':self.get_after_login_url(),
          'redirect':'true'
        }
        redirectUrl += '?' + urllib.urlencode(params)
        self.redirect( redirectUrl )
      else:
        self.clear_cookie('rdst')
        redirectUrl = config['CAS_LOGIN_URL']
        params = {
          'nextpage': base64.b64encode(self.get_after_login_url())
        }
        redirectUrl += '?' + urllib.urlencode(params)
        self.redirect( redirectUrl )

class EduSSOLogoutHandler(BaseHandler):
  @tornado.web.asynchronous
  @tornado.gen.coroutine
  def get(self):
    self.clear_all_cookies()
    redirectUrl = urlparse.urljoin(config['CAS_SERVER_HOST'],config['CAS_LOGOUT_ROUTE'])
    params = {
      'service':config['CAS_AFTER_LOGOUT']
    }
    redirectUrl += '?' + urllib.urlencode(params)
    self.redirect( redirectUrl )
    
class MainHandler(BaseHandler):
  @tornado.web.asynchronous
  @tornado.gen.coroutine
  @EduSSORequire
  def get(self):
    self.write("Index")

class HelloHandler(BaseHandler):
  @tornado.web.asynchronous
  @tornado.gen.coroutine
  @EduSSORequire
  def get(self):
    self.write("Hello, world")

routes = [
  (r"/login", EduSSOLoginHandler),
  (r"/exit",EduSSOLogoutHandler),
  (r"/", MainHandler),
  (r"/hello", HelloHandler)
]
settings = {
  'cookie_secret':'aGVsbG8lMkN3b3JsZA==',
  'login_url':'/login'
}
application = tornado.web.Application(routes,**settings)
 
 
if __name__ == "__main__":
  application.listen(5000)
  tornado.ioloop.IOLoop.instance().start()