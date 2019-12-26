"""Role based access"""

import logging
import arrow
from machine.plugins.base import MachineBasePlugin
from machine.plugins.decorators import listen_to, respond_to, required_settings

logger = logging.getLogger(__name__)


def _get_assigned_role(self, role):
    roles = self.storage.get(f'rbac:role:{role}', shared=True)
    roles = roles if roles else {}
    if role == 'root':
        roles = {
            self.settings['RBAC_ROLE_ROOT']: 1
        }
    return roles


def _notify_admins(self, title, message):
    roots = _get_assigned_role(self, 'root')
    admins = _get_assigned_role(self, 'admin')

    admins_to_be_notified = {**admins, **roots}
    for user_id in admins_to_be_notified:
        self.send_dm_webapi(
            user_id, f':warning: *{title}*', attachments=[{
                "color": "#ff0000",
                "text": message
            }]
        )


def _matching_roles(self, user_id, required_roles):
    matching_roles = 0
    for required_role in required_roles:
        assigned_roles = _get_assigned_role(self, required_role)
        if assigned_roles and user_id in assigned_roles:
            matching_roles = matching_roles + 1

    return matching_roles


def rbac_require_any_role(required_roles=[]):
    def middle(func):
        def wrapper(self, msg, **kwargs):
            if _matching_roles(self, msg.sender.id, required_roles):
                return func(self, msg, **kwargs)
            else:
                msg.say_webapi(
                    "I'm sorry, but you don't have access to that command", ephemeral=True)
                _notify_admins(
                    self,
                    f'Attempt to execute unauthorized command',
                    f'User {msg.at_sender} tried to execute the following command:'
                    f'```{msg.text}``` but lacks _one_ of these roles: {", ".join([f"`{role}`" for role in required_roles])}'
                )
                return
        return wrapper
    return middle


def rbac_require_all_roles(required_roles=[]):
    def middle(func):
        def wrapper(self, msg, **kwargs):
            if _matching_roles(self, msg.sender.id, required_roles) == len(required_roles):
                return func(self, msg, **kwargs)
            else:
                msg.say_webapi(
                    "I'm sorry, but you don't have access to that command", ephemeral=True)
                _notify_admins(
                    self,
                    f'Attempt to execute unauthorized command',
                    f'User {msg.at_sender} tried to execute the following command:'
                    f'```{msg.text}``` but lacks _all_ of these roles: {", ".join([f"`{role}`" for role in required_roles])}'
                )
                return
        return wrapper
    return middle


@required_settings(['RBAC_ROLE_ROOT'])
class RBACPlugin(MachineBasePlugin):

    @respond_to(regex=r'^grant\s+role\s+(?P<role>\w+)\s+to\s+<@(?P<user_id>\w+)>$')
    @rbac_require_any_role(['root', 'admin'])
    def grant_role_to_user(self, msg, role, user_id):
        if role == 'root':
            msg.say("Sorry, role `root` can only be granted via static configuration")
            return
        roles = _get_assigned_role(self, role)
        roles[user_id] = 1
        self.storage.set(f'rbac:role:{role}', roles, shared=True)
        msg.say(f'Role `{role}` has been granted to <@{user_id}>')

    @respond_to(regex=r'^revoke\s+role\s+(?P<role>\w+)\s+from\s+<@(?P<user_id>\w+)>$')
    @rbac_require_any_role(['root', 'admin'])
    def revoke_role_from_user(self, msg, role, user_id):
        assigned_roles = _get_assigned_role(self, role)
        if user_id in assigned_roles:
            del assigned_roles[user_id]
            self.storage.set(f'rbac:role:{role}', assigned_roles, shared=True)
            msg.say(f'Role `{role}` has been revoked from <@{user_id}>')
        else:
            msg.say(f'Role <@{user_id}> does not have role `{role}`')

    @respond_to(regex=r'^who\s+has\s+role\s+(?P<role>\w+)')
    @rbac_require_any_role(['root', 'admin'])
    def who_has_role(self, msg, role):
        assigned_roles = _get_assigned_role(self, role)
        if len(assigned_roles):
            msg.say(
                f'Role `{role}` has been granted to {", ".join([f"<@{user_id}>" for user_id in assigned_roles.keys()])}')
        else:
            msg.say(f'No one have been assigned role `{role}`')
