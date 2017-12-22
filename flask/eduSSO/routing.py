import flask
from xmltodict import parse
from flask import current_app
from .cas_urls import (create_url,create_cas_login_url,create_cas_logout_url,create_cas_validate_url)
import base64,time,re,json

try:
    from urllib import urlopen
except ImportError:
    from urllib.request import urlopen

blueprint = flask.Blueprint('cas', __name__)


@blueprint.route('/login/')
def login():
    """
    This route has two purposes. First, it is used by the user
    to login. Second, it is used by the CAS to respond with the
    `ticket` after the user logs in successfully.

    When the user accesses this url, they are redirected to the CAS
    to login. If the login was successful, the CAS will respond to this
    route with the ticket in the url. The ticket is then validated.
    If validation was successful the logged in username is saved in
    the user's session under the key `CAS_USERNAME_SESSION_KEY` and
    the user's attributes are saved under the key
    'CAS_USERNAME_ATTRIBUTE_KEY'
    """

    cas_token_session_key = current_app.config['CAS_TOKEN_SESSION_KEY']
    if not flask.session.get("__ast"):
        redirect_url = create_cas_login_url(
            current_app.config['CAS_SERVER_HOST'],
            current_app.config['CAS_SERVER_ROUTE'],
            current_app.config['CAS_AFTER_LOGIN']
            )
        redirect_url +=  "&redirect=true"
        flask.session["__ast"] = time.time()
    else:
        flask.session["__ast"] = ""
        redirect_url = current_app.config['CAS_LOGIN_URL'] + "?nextpage=" + base64.b64encode(current_app.config['CAS_AFTER_LOGIN'])
    
    if 'ticket' in flask.request.args:
        flask.session[cas_token_session_key] = flask.request.args['ticket']
        redirect_url = current_app.config['CAS_AFTER_LOGIN']
    if cas_token_session_key in flask.session:
        if validate(flask.session[cas_token_session_key]):
            if 'CAS_AFTER_LOGIN_SESSION_URL' in flask.session:
                redirect_url = flask.session.pop('CAS_AFTER_LOGIN_SESSION_URL')
            else:
                redirect_url = flask.url_for(
                    current_app.config['CAS_AFTER_LOGIN'])
        else:
            del flask.session[cas_token_session_key]
    current_app.logger.debug('Redirecting to: {0}'.format(redirect_url))

    return flask.redirect(redirect_url)
    # return flask.redirect(current_app.config['CAS_AFTER_LOGIN'])


@blueprint.route('/logout/')
def logout():
    """
    When the user accesses this route they are logged out.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
    cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']

    if cas_username_session_key in flask.session:
        del flask.session[cas_username_session_key]

    if cas_attributes_session_key in flask.session:
        del flask.session[cas_attributes_session_key]

    if(current_app.config['CAS_AFTER_LOGOUT'] != None):
        redirect_url = create_cas_logout_url(
            current_app.config['CAS_SERVER_HOST'],
            current_app.config['CAS_LOGOUT_ROUTE'],
            current_app.config['CAS_AFTER_LOGOUT'])
    else:
        redirect_url = create_cas_logout_url(
            current_app.config['CAS_SERVER_HOST'],
            current_app.config['CAS_LOGOUT_ROUTE'])
    current_app.logger.debug('Redirecting to: {0}'.format(redirect_url))
    return flask.redirect(redirect_url)


def validate(ticket):
    """
    Will attempt to validate the ticket. If validation fails, then False
    is returned. If validation is successful, then True is returned
    and the validated username is saved in the session under the
    key `CAS_USERNAME_SESSION_KEY` while tha validated attributes dictionary
    is saved under the key 'CAS_ATTRIBUTES_SESSION_KEY'.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
    cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']

    current_app.logger.debug("validating token {0}".format(ticket))

    cas_validate_url = create_cas_validate_url(
        current_app.config['CAS_SERVER_HOST'],
        current_app.config['CAS_VALIDATE_ROUTE'],
        current_app.config['CAS_AFTER_LOGIN'],
        ticket)
    cas_validate_url += "&callback=callback"
    current_app.logger.debug("Making GET request to {0}".format(
        cas_validate_url))

    validRet = {}
    isValid = False

    try:
        callbackRet = urlopen(cas_validate_url).read().strip()
        p = re.compile("callback\((.*)\)")
        m = p.match(callbackRet)
        validRet = json.loads(m.group(1))
        isValid = True if validRet.get("code",0) else False
    except ValueError:
        current_app.logger.error("CAS returned unexpected result")

    if isValid:
        current_app.logger.debug("valid")
        username = validRet['data']["openId"]
        attributes = validRet['data']["attributes"]
        flask.session[cas_username_session_key] = username
        flask.session[cas_attributes_session_key] = attributes
    else:
        current_app.logger.debug("invalid")

    return isValid
