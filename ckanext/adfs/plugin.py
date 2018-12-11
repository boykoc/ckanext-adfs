"""
Plugin for our ADFS
"""
import logging
import ckan.lib.base as base
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import uuid
from validation import validate_saml
from metadata import get_certificates, get_federation_metadata, get_wsfed
from extract import get_user_info
from ckan.config.routing import SubMapper

from ckan.common import session, request, response
from flask import Blueprint

log = logging.getLogger(__name__)


# Some awful XML munging.
WSFED_ENDPOINT = ''
WTREALM = toolkit.config['adfs_wtrealm']
METADATA = get_federation_metadata(toolkit.config['adfs_metadata_url'])
WSFED_ENDPOINT = get_wsfed(METADATA)

if not (WSFED_ENDPOINT):
    raise ValueError('Unable to read WSFED_ENDPOINT values for ADFS plugin.')


def adfs_organization_name():
    return toolkit.config.get('adfs_organization_name', 'our organization')


def adfs_authentication_endpoint():
    url_template = '{}?wa=wsignin1.0&wreq=xml&wtrealm={}'
    return url_template.format(WSFED_ENDPOINT, WTREALM)


def is_adfs_user():
    return session.get('adfs-user')


def login():
    """
    A custom home controller for receiving ADFS authorization responses.
    """
    
    """
    Handle eggsmell request from the ADFS redirect_uri.
    """
    try:
        eggsmell = toolkit.request.form['wresult']
    except Exception as ex:
        log.error('Missing eggsmell. `wresult` param does not exist.')
        log.error(ex)
        toolkit.h.flash_error(u'Not able to successfully authenticate.')
        return toolkit.redirect_to(u'/user/login')

    # We grab the metadata for each login because due to opaque
    # bureaucracy and lack of communication the certificates can be
    # changed. We looked into this and took made the call based upon lack
    # of user problems and tech being under our control vs the (small
    # amount of) latency from a network call per login attempt.
    metadata = get_federation_metadata(toolkit.config['adfs_metadata_url'])
    x509_certificates = get_certificates(metadata)
    if not validate_saml(eggsmell, x509_certificates):
        raise ValueError('Invalid signature')
    username, email, firstname, surname = get_user_info(eggsmell)

    if not email:
        log.error('Unable to login with ADFS')
        log.error(eggsmell)
        raise ValueError('No email returned with ADFS')

    user = _get_user(username)
    if user:
        # Existing user
        log.info('Logging in from ADFS with user: {}'.format(username))
    elif toolkit.config.get('adfs_create_user', False):
        # New user, so create a record for them if configuration allows.
        log.info('Creating user from ADFS')
        log.info('email: {} firstname: {} surname: {}'.format(email,
                 firstname.encode('utf8'), surname.encode('utf8')))
        log.info('Generated username: {}'.format(username))
        # TODO: Add the new user to the NHSEngland group? Check this!
        user = toolkit.get_action('user_create')(
            context={'ignore_auth': True},
            data_dict={'name': username,
                       'fullname': firstname + ' ' + surname,
                       'password': str(uuid.uuid4()),
                       'email': email})
    else:
        log.error('Cannot create new ADFS users. User must already exist due to configuration.')
        log.error(eggsmell)
        contact_email = toolkit.config.get('adfs_contact_email', 'your administrator')
        toolkit.abort(403, "Oops, you don't have access. Please email %s for access." % (contact_email))
    
    # Log the user in programatically.
    # Reference: ckan/views/user.py
    # By this point we either have a user or created one and they're good to login.
    resp = toolkit.h.redirect_to(u'user.logged_in')

    '''Set the repoze.who cookie to match a given user_id'''
    if u'repoze.who.plugins' in request.environ:
        rememberer = request.environ[u'repoze.who.plugins'][u'friendlyform']
        identity = {u'repoze.who.userid': username}
        resp.headers.extend(rememberer.remember(request.environ, identity))

    return resp


class ADFSPlugin(plugins.SingletonPlugin):
    """
    Log us in via the ADFSes
    """
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config):
        """
        Add our templates to CKAN's search path
        """
        toolkit.add_template_directory(config, 'templates')

    def get_helpers(self):
        return dict(is_adfs_user=is_adfs_user,
                    adfs_authentication_endpoint=adfs_authentication_endpoint,
                    adfs_organization_name=adfs_organization_name)

    def get_blueprint(self):
        blueprint = Blueprint('adfs_redirect_uri', self.__module__)
        rules = [
            ('/adfs/signin/', 'login', login)
        ]
        for rule in rules:
            blueprint.add_url_rule(*rule, methods=['POST'])

        return blueprint

    def identify(self):
        """
        Called to identify the user.
        TODO: Next release of CKAN remove this and set to `pass`.
              "Nothing to do here, let CKAN handle identifying the user.
               If ADFS, we login above and then CKAN will identify user."
        """
        # Must set user to prevent `AttributeError: '_Globals' object has no attribute 'user'`
        if not getattr(toolkit.c, u'user', None):
            # Set to none if no user as per CKAN issue #4247.
            # identify_user() also normally tries to set to None
            # but not working as of CKAN 2.8.0.
            toolkit.c.user = None

    def login(self):
        """
        Called at login.
        Nothing to do here. If default CKAN login, let CKAN do it's thing.
        If ADFS login, user is logged in above and this isn't called as we 
        by-pass the login_handler setup by CKAN and repoze.who.
        """
        pass

    def logout(self):
        """
        Called at logout.
        Nothing to do here, let repoze.who / CKAN handle logout.
        """
        pass

    def abort(self, status_code, detail, headers, comment):
        """
        Called on abort.  This allows aborts due to authorization issues
        to be overridden.
        """
        return (status_code, detail, headers, comment)


def _get_user(name):
    """
    Return the CKAN user with the given user name, or None.
    """
    try:
        return toolkit.get_action('user_show')(data_dict = {'id': name})
    except toolkit.ObjectNotFound:
        return None


class FileNotFoundException(Exception):
    pass