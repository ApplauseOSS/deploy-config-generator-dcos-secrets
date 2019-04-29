from deploy_config_generator.output import OutputPluginBase
from deploy_config_generator.utils import json_dump


class OutputPlugin(OutputPluginBase):

    NAME = 'dcos_secrets'
    DESCR = 'DC/OS Secrets output plugin'
    FILE_EXT = '.json'

    DEFAULT_CONFIG = {
        'fields': {
            'secrets': dict(
                name=dict(
                    required=True,
                    type='str',
                    description='Name of the secret',
                ),
                type=dict(
                    default='password',
                    type='str',
                    description='Type of secret (password, certificate)',
                ),
                env_var=dict(
                    type='str',
                    description='Name of environment variable to pull secret value from',
                ),
            ),
        }
    }

    def generate_output(self, app_vars):
        data = dict()
        for key, value in app_vars['APP'].items():
            if value is not None:
                data[key] = value
        output = json_dump(self._template.render_template(data, app_vars))
        return output
