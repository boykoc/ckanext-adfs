import ckan.lib.base as base
import ckan.model as model
import ckan.lib.helpers as h
import ckan.authz as authz
import ckan.logic as logic
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.lib.authenticator as authenticator
import ckan.plugins as p
from plugin import is_adfs_user

from ckan.common import _, c, g, request, response
from ckan.controllers.user import UserController

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config


check_access = logic.check_access
get_action = logic.get_action
NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
ValidationError = logic.ValidationError
UsernamePasswordError = logic.UsernamePasswordError

DataError = dictization_functions.DataError
unflatten = dictization_functions.unflatten


class ADFSUserController(UserController):
    def _save_edit(self, user_id, context):
    '''Override CKAN user controller action.

    ADFS user specific functionality is included.
    ADFS users should not be able to modify email, 
    username and password. Password is not rendered
    in template.
    '''
        try:
            if user_id in (c.userobj.id, c.userobj.name):
                current_user = True
            else:
                current_user = False
            old_username = c.userobj.name

            data_dict = logic.clean_dict(unflatten(
                logic.tuplize_dict(logic.parse_params(request.params))))
            context['message'] = data_dict.get('log_message', '')
            data_dict['id'] = user_id

            email_changed = data_dict['email'] != c.userobj.email

            # When reseting password or email verify user.
            # Using data_dict.get() as passwords are not available for ADFS users.
            if (data_dict.get('password1') and data_dict.get('password2')) \
                    or email_changed:
                identity = {'login': c.user,
                            'password': data_dict['old_password']}
                auth = authenticator.UsernamePasswordAuthenticator()

                if auth.authenticate(request.environ, identity) != c.user:
                    raise UsernamePasswordError

            # MOAN: Do I really have to do this here?
            if 'activity_streams_email_notifications' not in data_dict:
                data_dict['activity_streams_email_notifications'] = False

            # If ADFS user block changing  username email.
            if is_adfs_user():
                data_dict['name'] = old_username
                data_dict['email'] = c.userobj.email

            user = get_action('user_update')(context, data_dict)
            h.flash_success(_('Profile updated'))

            if current_user and data_dict['name'] != old_username:
                # Changing currently logged in user's name.
                # Update repoze.who cookie to match
                set_repoze_user(data_dict['name'])
            h.redirect_to(controller='user', action='read', id=user['name'])
        except NotAuthorized:
            abort(401, _('Unauthorized to edit user %s') % user_id)
        except NotFound, e:
            abort(404, _('User not found'))
        except DataError:
            abort(400, _(u'Integrity Error'))
        except ValidationError, e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.edit(user_id, data_dict, errors, error_summary)
        except UsernamePasswordError:
            errors = {'oldpassword': [_('Password entered was incorrect')]}
            error_summary = {_('Old Password'): _('incorrect password')}
            return self.edit(user_id, data_dict, errors, error_summary)