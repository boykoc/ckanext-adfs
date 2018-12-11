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

from ckan.common import session


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


class ADFSPlugin(plugins.SingletonPlugin):
    """
    Log us in via the ADFSes
    """
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IRoutes)
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

    def before_map(self, map):
        """
        Called before the routes map is generated. ``before_map`` is before any
        other mappings are created so can override all other mappings.

        :param map: Routes map object
        :returns: Modified version of the map object
        """
        # Route requests for our WAAD redirect URI to a custom controller.
        map.connect(
            'adfs_redirect_uri', '/adfs/signin/',
            controller='ckanext.adfs.plugin:ADFSRedirectController',
            action='login')
        # Route user edits to a custom contoller
        with SubMapper(map, controller='ckanext.adfs.user:ADFSUserController') as m:
            m.connect('/user/edit', action='edit')
            m.connect('user_edit', '/user/edit/{id:.*}', action='edit',
                      ckan_icon='cog')
        return map

    def after_map(self, map):
        """
        Called after routes map is set up. ``after_map`` can be used to
        add fall-back handlers.

        :param map: Routes map object
        :returns: Modified version of the map object
        """
        return map

    def identify(self):
        """
        Called to identify the user.
        """
        user = session.get('adfs-user')
        if user:
            toolkit.c.user = user
        else:
            # Set to none if no user as per CKAN issue #4247.
            # identify_user() also normally tries to set to None
            # but not working as of CKAN 2.8.0.
            toolkit.c.user = None

    def login(self):
        """
        Called at login.
        """
        pass

    def logout(self):
        """
        Called at logout.
        """
        keys_to_delete = [key for key in session
                          if key.startswith('adfs')]
        if keys_to_delete:
            for key in keys_to_delete:
                del session[key]
            session.save()


    def abort(self, status_code, detail, headers, comment):
        """
        Called on abort.  This allows aborts due to authorization issues
        to be overriden.
        """
        return (status_code, detail, headers, comment)


def _get_user(name):
    """
    Return the CKAN user with the given user name, or None.
    Check state, state: deleted can still login but gets a blank page because
    CKAN is handling authorization later as well.
    """
    try:
        user = toolkit.get_action('user_show')(data_dict = {'id': name})
        if user['state'] == 'active':
            return user
        else:
            raise toolkit.ObjectNotFound
    except toolkit.ObjectNotFound:
        return None


class FileNotFoundException(Exception):
    pass


class ADFSRedirectController(toolkit.BaseController):
    """
    A custom home controller for receiving ADFS authorization responses.
    """

    def login(self):
        """
        Handle eggsmell request from the ADFS redirect_uri.
        """
        eggsmell = toolkit.request.POST['wresult']
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
        
        session['adfs-user'] = username
        session['adfs-email'] = email
        session.save()
        toolkit.redirect_to(controller='user', action='dashboard', id=email)
        return
