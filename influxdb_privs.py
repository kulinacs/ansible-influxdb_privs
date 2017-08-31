from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

try:
    from influxdb import InfluxDBClient
    HAS_INFLUXDB = True
except ImportError:
    HAS_INFLUXDB = False

from ansible.module_utils.basic import AnsibleModule

priv_map = {'no privileges': None,
            'all privileges': 'all',
            'write': 'write',
            'read': 'read'}

def connect(module):
    '''Connect to influxdb and return the client'''
    client = InfluxDBClient(
        host=module.params['hostname'],
        port=module.params['port'],
        username=module.params['authuser'],
        password=module.params['authpass'],
    )
    return client

def add_priv(client, user, database, priv, check):
    '''Add a new privilege'''
    if not check:
        client.grant_privilege(priv, database, user)

def del_priv(client, user, database, priv, check):
    '''Revoke an existing privilege'''
    if not check:
        client.revoke_privilege(priv, database, user)
       
def main():
    module = AnsibleModule(
        argument_spec=dict(
            hostname=dict(required=True, type='str'),
            port=dict(default=8086, type='int'),
            authuser=dict(default='root', type='str'),
            authpass=dict(default='root', type='str', no_log=True),
            user=dict(required=True, type='str'),
            database=dict(required=True, type='str'),
            priv=dict(required=True, type='str', choices=['read', 'write', 'all']),
            grant_option=dict(required=True, type='bool')
        ),
        supports_check_mode=True
    )

    if not HAS_INFLUXDB:
        module.fail_json(msg='influxdb module must be installed')

    client = connect(module)

    # Gather current user state
    privs = client.get_list_privileges(module.params['user'])
    priv_dict = [priv for priv in privs if priv['database'] == module.params['database']]
    if len(priv_dict) == 1:
        priv_dict = priv_dict[0]
        user_priv = priv_map[priv_dict['privilege'].encode('ascii','ignore').lower()]
    else:
        priv_dict = None
        user_priv = None

    changed = False

    if module.params['grant_option']:
        if priv_dict == None or user_priv == None:
            changed = True
            add_priv(client, module.params['user'], module.params['database'], module.params['priv'], module.check_mode)
        else:
            if module.params['priv'] != user_priv:
                changed = True
                del_priv(client, module.params['user'], module.params['database'], user_priv, module.check_mode)
                add_priv(client, module.params['user'], module.params['database'], module.params['priv'], module.check_mode)
    else:
        if priv_dict != None and module.params['priv'] == user_priv:
            changed = True
            del_priv(client, module.params['user'], module.params['database'], module.params['priv'], module.check_mode)

    module.exit_json(changed=changed)

if __name__ == '__main__':
    main()
