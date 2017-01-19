#!/usr/bin/env python
"""
The Configuration object parses all configuration files, loads them into
memory, derives some settings and provides framework modules with a central
repository to get info.
"""

import os
import re
import logging
import socket
from copy import deepcopy
from urlparse import urlparse
from collections import defaultdict

from framework.dependency_management.dependency_resolver import BaseComponent
from framework.dependency_management.interfaces import ConfigInterface
from framework.lib.exceptions import PluginAbortException, DBIntegrityException, UnresolvableTargetException
from framework.lib.general import cprint
from framework.db import target_manager
from framework.utils import is_internal_ip, directory_access, FileOperations


REPLACEMENT_DELIMITER = "@@@"
REPLACEMENT_DELIMITER_LENGTH = len(REPLACEMENT_DELIMITER)
CONFIG_TYPES = ['string', 'other']


class Config(BaseComponent, ConfigInterface):

    COMPONENT_NAME = "config"

    RootDir = None
    OwtfPid = None
    Profiles = {
        "GENERAL_PROFILE": None,
        "RESOURCES_PROFILE": None,
        "WEB_PLUGIN_ORDER_PROFILE": None,
        "NET_PLUGIN_ORDER_PROFILE": None,
        "MAPPING_PROFILE": None
    }
    Target = None

    def __init__(self, root_dir, owtf_pid):
        self.register_in_service_locator()
        self.root_dir = root_dir
        self.owtf_pid = owtf_pid
        self.resource = None
        self.error_handler = None
        self.target = None
        self.config = None
        self.db_plugin = None
        self.worklist_manager = None
        self.initialize_attributes()
        # key can consist alphabets, numbers, hyphen & underscore.
        self.search_regex = re.compile('%s([a-zA-Z0-9-_]*?)%s' % (REPLACEMENT_DELIMITER, REPLACEMENT_DELIMITER))
        # Available profiles = g -> General configuration, n -> Network plugin
        # order, w -> Web plugin order, r -> Resources file
        self.initialize_attributes()
        self.load_framework_config_from_file(os.path.join(self.RootDir, 'framework', 'config', 'framework_config.cfg'))

    def init(self):
        """Initialize the Option resources."""
        self.resource = self.get_component("resource")
        self.error_handler = self.get_component("error_handler")
        self.target = self.get_component("target")
        self.db_plugin = self.get_component("db_plugin")
        self.worklist_manager = self.get_component("worklist_manager")

    def initialize_attributes(self):
        self.config = defaultdict(list)  # General configuration information.
        for type in CONFIG_TYPES:
            self.config[type] = {}

    def load_framework_config_from_file(self, config_path):
        """Load the configuration from into a global dictionary."""
        if 'framework_config' not in config_path:
            cprint("Loading Config from: %s.." % config_path)
        config_file = FileOperations.open(config_path, 'r')
        self.set('FRAMEWORK_DIR', self.RootDir)  # Needed Later.
        for line in config_file:
            try:
                key = line.split(':')[0]
                if key[0] == '#':  # Ignore comment lines.
                    continue
                value = line.replace("%s: " % key, "").strip()
                self.set(key,
                         self.multiple_replace(value, {'FRAMEWORK_DIR': self.root_dir, 'OWTF_PID': str(self.owtf_pid)}))
            except ValueError:
                self.error_handler.FrameworkAbort("Problem in config file: %s -> Cannot parse line: %s" % (config_path,
                                                                                                           line))

    def convert_str_to_bool(self, string):
        return (not(string in ['False', 'false', 0, '0']))

    def process_options_phase1(self, options):
        """Process the options from the CLI.

        :param dict options: Options coming from the CLI.

        """
        # Backup the raw CLI options in case they are needed later.
        self.cli_options = deepcopy(options)
        self.load_profiles(options['Profiles'])

    def process_options_phase2(self, options):
        target_urls = self.load_targets(options)
        self.load_works(target_urls, options)

    def load_works(self, target_urls, options):
        """Select the proper plugins to run against the target URLs.

        :param list target_urls: the target URLs
        :param dict options: the options from the CLI.

        """
        for target_url in target_urls:
            if target_url:
                self.load_work(target_url, options)

    def load_work(self, target_url, options):
        """Select the proper plugins to run against the target URL.

        .. note::

            If plugin group is not specified and several targets are fed, OWTF
            will run the WEB plugins for targets that are URLs and the NET
            plugins for the ones that are IP addresses.

        :param str target_url: the target URL
        :param dict options: the options from the CLI.

        """
        target = self.target.get_target_config({'target_url': target_url})
        group = options['PluginGroup']
        if options['OnlyPlugins'] is None:
            # If the plugin group option is the default one (not specified by the user).
            if group is None:
                group = 'web'  # Default to web plugins.
                # Run net plugins if target does not start with http (see #375).
                if not target_url.startswith(('http://', 'https://')):
                    group = 'network'
            filter_data = {'type': options['PluginType'], 'group': group}
        else:
            filter_data = {"code": options.get("OnlyPlugins"), "type": options.get("PluginType")}
        plugins = self.db_plugin.GetAll(filter_data)
        if not plugins:
            logging.error("No plugin found matching type '%s' and group '%s' for target '%s'!" %
                          (options['PluginType'], group, target))
        self.worklist_manager.add_work(target, plugins, force_overwrite=options["Force_Overwrite"])

    def get_profile_path(self, profile_name):
        return self.Profiles.get(profile_name, None)

    def load_profiles(self, profiles):
        # This prevents python from blowing up when the Key does not exist :)
        self.profiles = defaultdict(list)
        # Now override with User-provided profiles, if present.
        self.profiles["GENERAL_PROFILE"] = profiles.get('g', None) or \
            self.framework_config_get("DEFAULT_GENERAL_PROFILE")
        # Resources profile
        self.profiles["RESOURCES_PROFILE"] = profiles.get('r', None) or \
            self.framework_config_get("DEFAULT_RESOURCES_PROFILE")
        # web plugin order
        self.profiles["WEB_PLUGIN_ORDER_PROFILE"] = profiles.get('w', None) or \
            self.framework_config_get("DEFAULT_WEB_PLUGIN_ORDER_PROFILE")
        # network plugin order
        self.profiles["NET_PLUGIN_ORDER_PROFILE"] = profiles.get('n', None) or \
            self.framework_config_get("DEFAULT_NET_PLUGIN_ORDER_PROFILE")
        # mapping
        self.profiles["MAPPING_PROFILE"] = profiles.get('m', None) or \
            self.framework_config_get("DEFAULT_MAPPING_PROFILE")

    def load_targets(self, options):
        scope = options['Scope']
        if options['PluginGroup'] == 'auxiliary':
            scope = self.get_aux_target(options)
        added_targets = []
        for target in scope:
            try:
                self.target.AddTarget(target)
                added_targets.append(target)
            except DBIntegrityException:
                logging.warning("%s already exists in DB" % target)
                added_targets.append(target)
            except UnresolvableTargetException as e:
                logging.error("%s" % e.parameter)
        return added_targets

    def get_aux_target(self, options):
        """
        This function returns the target for auxiliary plugins from the parameters provided
        """
        # targets can be given by different params depending on the aux plugin we are running
        # so "target_params" is a list of possible parameters by which user can give target
        target_params = ['RHOST', 'TARGET', 'SMB_HOST', 'BASE_URL', 'SMTP_HOST']
        plugin_params = self.get_component("plugin_params")
        targets = None
        if plugin_params.process_args():
            for param in target_params:
                if param in plugin_params.Args:
                    targets = plugin_params.Args[param]
                    break  # it will capture only the first one matched
            repeat_delim = ','
            if targets is None:
                logging.error("Aux target not found! See your plugin accepted parameters in ./plugins/ folder")
                return []
            if 'REPEAT_DELIM' in plugin_params.args:
                repeat_delim = plugin_params.args['REPEAT_DELIM']
            return targets.split(repeat_delim)
        else:
            return []

    def multiple_replace(self, text, replace_dict):
        new_text = text
        for key in self.search_regex.findall(new_text):
            # Check if key exists in the replace dict ;)
            if replace_dict.get(key, None):
                # A recursive call to remove all level occurences of place
                # holders.
                new_text = new_text.replace(REPLACEMENT_DELIMITER + key + REPLACEMENT_DELIMITER,
                                            self.multiple_replace(replace_dict[key], replace_dict))
        return new_text

    def load_proxy_config(self, options):
        if options['InboundProxy']:
            if len(options['InboundProxy']) == 1:
                options['InboundProxy'] = [self.get('INBOUND_PROXY_IP'), options['InboundProxy'][0]]
        else:
            options['InboundProxy'] = [self.get('INBOUND_PROXY_IP'), self.get('INBOUND_PROXY_PORT')]
        self.set('INBOUND_PROXY_IP', options['InboundProxy'][0])
        self.set('INBOUND_PROXY_PORT', options['InboundProxy'][1])
        self.set('INBOUND_PROXY', ':'.join(options['InboundProxy']))
        self.set('PROXY', ':'.join(options['InboundProxy']))

    def get_resources(self, resource_type):
        """Replace the resources placeholders with the relevant config."""
        return self.resource.GetResources(resource_type)

    def get_resource_list(self, resource_type_list):
        return self.resource.GetResourceList(resource_type_list)

    def get_raw_resource(self, resource_type):
        return self.resources[resource_type]

    def derive_config_from_url(self, target_URL):
        """Automatically find target information based on target name.

        If target does not start with 'http' or 'https', then it is considered as a network target.

        + target host
        + target port
        + target url
        + target path
        + etc.
        """
        target_config = dict(target_manager.TARGET_CONFIG)
        target_config['target_url'] = target_URL
        try:
            parsed_URL = urlparse(target_URL)
            if not parsed_URL.hostname and not parsed_URL.path:  # No hostname and no path, urlparse failed.
                raise ValueError
        except ValueError:  # Occurs sometimes when parsing invalid IPv6 host for instance
            raise UnresolvableTargetException("Invalid hostname '%s'" % str(target_URL))

        host = parsed_URL.hostname
        if not host:  # Happens when target is an IP (e.g. 127.0.0.1)
            host = parsed_URL.path  # Use the path as host (e.g. 127.0.0.1 => host = '' and path = '127.0.0.1')
            host_path = host
        else:
            host_path = parsed_URL.hostname + parsed_URL.path

        URL_scheme = parsed_URL.scheme
        protocol = parsed_URL.scheme
        if parsed_URL.port is None:  # Port is blank: Derive from scheme (default port set to 80).
            try:
                host, port = host.rsplit(':')
            except ValueError:  # Raised when target doesn't contain the port (e.g. google.fr)
                port = '80'
                if 'https' == URL_scheme:
                    port = '443'
        else:  # Port found by urlparse.
            port = str(parsed_URL.port)

        # Needed for google resource search.
        target_config['host_path'] = host_path
        # Some tools need this!
        target_config['url_scheme'] = URL_scheme
        # Some tools need this!
        target_config['port_number'] = port
        # Set the top URL.
        target_config['host_name'] = host

        host_IP = self.get_ip_from_hostname(host)
        host_IPs = self.get_ips_from_hostname(host)
        target_config['host_ip'] = host_IP
        target_config['alternative_ips'] = host_IPs

        ip_url = target_config['target_url'].replace(host, host_IP)
        target_config['ip_url'] = ip_url
        target_config['top_domain'] = target_config['host_name']

        hostname_chunks = target_config['host_name'].split('.')
        if target_config['target_url'].startswith(('http', 'https')):  # Target considered as hostname (web plugins)
            if not target_config['host_name'] in target_config['alternative_ips']:
                target_config['top_domain'] = '.'.join(hostname_chunks[1:])
            # Set the top URL (get "example.com" from "www.example.com").
            target_config['top_url'] = "%s://%s:%s" % (protocol, host, port)
        else:  # Target considered as IP (net plugins)
            target_config['top_domain'] = ''
            target_config['top_url'] = ''
        return target_config

    def derive_output_config_from_url(self, target_URL):
        # Set the output directory.
        self.set('host_output', "%s/%s" % (self.get('OUTPUT_PATH'), self.get('host_ip')))
        # Set the output directory.
        self.set('port_output', "%s/%s" % (self.get('host_output'), self.get('port_number')))
        URL_info_ID = target_URL.replace('/', '_').replace(':', '')
        # Set the URL output directory (plugins will save their data here).
        self.set('url_output', "%s/%s/" % (self.get('port_output'), URL_info_ID))
        # Set the partial results path.
        self.set('partial_url_output_path', '%spartial' % self.get('url_output'))
        self.set('PARTIAL_REPORT_REGISTER', "%s/partial_report_register.txt" % self.get('partial_url_output_path'))

        # Tested in FF 8: Different directory = Different localStorage!! -> All
        # localStorage-dependent reports must be on the same directory.
        # IMPORTANT: For localStorage to work Url reports must be on the same
        # directory.
        self.set('HTML_DETAILED_REPORT_PATH', "%s/%s.html" % (self.get('OUTPUT_PATH'), URL_info_ID))
        # IMPORTANT: For localStorage to work Url reports must be on the same
        # directory.
        self.set('URL_REPORT_LINK_PATH', "%s/index.html" % self.get('OUTPUT_PATH'))

        if not self.get('SIMULATION'):
            FileOperations.create_missing_dirs(self.Get('host_output'))

    def get_file_name(self, setting, partial=False):
        path = self.get(setting)
        if partial:
            return os.path.basename(path)
        return path

    def get_html_transaction_log(self, partial=False):
        return self.get_file_name('TRANSACTION_LOG_HTML', partial)

    def get_txt_transaction_log(self, partial=False):
        return self.get_file_name('TRANSACTION_LOG_TXT', partial)

    def hostname_is_ip(self, hostname, ip):
        """Test if the hostname is an IP.

        :param str hostname: the hostname of the target.
        :param str ip: the IP (v4 or v6) of the target.

        :return: ``True`` if the hostname is an IP, ``False`` otherwise.
        :rtype: :class:`bool`

        """
        return hostname == ip

    def get_ip_from_hostname(self, hostname):
        ip = ''
        # IP validation based on @marcwickenden's pull request, thanks!
        for socket in [socket.AF_INET, socket.AF_INET6]:
            try:
                socket.inet_pton(socket, hostname)
                ip = hostname
                break
            except socket.error:
                continue
        if not ip:
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                raise UnresolvableTargetException("Unable to resolve: '%s'" % hostname)

        ipchunks = ip.strip().split("\n")
        alternative_IPs = []
        if len(ipchunks) > 1:
            ip = ipchunks[0]
            cprint("%s has several IP addresses: (%s).Choosing first: %s" % (hostname, "".join(ipchunks)[0:-3], ip))
            alternative_IPs = ipchunks[1:]
        self.set('alternative_ips', alternative_IPs)
        ip = ip.strip()
        self.set('INTERNAL_IP', is_internal_ip(ip))
        logging.info("The IP address for %s is: '%s'" % (hostname, ip))
        return ip

    def get_ips_from_hostname(self, hostname):
        ip = ''
        # IP validation based on @marcwickenden's pull request, thanks!
        for socket in [socket.AF_INET, socket.AF_INET6]:
            try:
                socket.inet_pton(socket, hostname)
                ip = hostname
                break
            except socket.error:
                continue
        if not ip:
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                raise UnresolvableTargetException("Unable to resolve: '%s'" % hostname)

        ipchunks = ip.strip().split("\n")
        return ipchunks

    def is_set(self, key):
        key = self.padkey(key)
        config = self.get_config()
        for type in CONFIG_TYPES:
            if key in config[type]:
                return True
        return False

    def GetKeyValue(self, key):
        # Gets the right config for target / general.
        config = self.GetConfig()
        for type in CONFIG_TYPES:
            if key in config[type]:
                return config[type][key]

    def padkey(self, key):
        # Add delimiters.
        return REPLACEMENT_DELIMITER + key + REPLACEMENT_DELIMITER

    def strip_key(self, key):
        return key.replace(REPLACEMENT_DELIMITER, '')

    def framework_config_get(self, key):
        """Transparently gets config info from Target or General."""
        try:
            key = self.padkey(key)
            return self.get_key_val(key)
        except KeyError:
            message = "The configuration item: %s does not exist!" % key
            self.error_handler.Add(message)
            # Raise plugin-level exception to move on to next plugin.
            raise PluginAbortException(message)

    def get_logs_dir(self):
        """
        Get log directory by checking if abs or relative path is provided in
        config file
        """
        logs_dir = self.framework_config_get("LOGS_DIR")
        # Check access for logsdir parent directory because logsdir may not be created.
        if os.path.isabs(logs_dir) and directory_access(os.path.dirname(logs_dir), "w+"):
            return logs_dir
        else:
            return os.path.join(self.get_output_dir(), logs_dir)

    def get_log_path(self, process_name):
        """
        Get the log file path based on the process name
        """
        log_file_name = "%s.log" % process_name
        return os.path.join(self.get_logs_dir(), log_file_name)

    def get_as_list(self, key_list):
        value_list = []
        for key in key_list:
            value_list.append(self.framework_config_get(key))
        return value_list

    def get_header_list(self, key):
        return self.framework_config_get(key).split(',')

    def set_general(self, type, key, value):
        self.config[type][key] = value

    def set(self, key, value):
        """Set config items in Target-specific or General config."""
        # Store config in "replacement mode", that way we can multiple-replace
        # the config on resources, etc.
        key = REPLACEMENT_DELIMITER + key + REPLACEMENT_DELIMITER
        type = 'other'
        # Only when value is a string, store in replacements config.
        if isinstance(value, str):
            type = 'string'
        return self.set_general(type, key, value)

    def get_framework_config_dict(self):
        return self.get_config()['string']

    def get_replacement_dict(self):
        return {"FRAMEWORK_DIR": self.root_dir}

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def get_config(self):
        return self.config

    def show(self):
        cprint("Configuration settings")
        for k, v in self.get_config().items():
            cprint("%s => %s" % (str(k), str(v)))

    def get_output_dir(self):
        output_dir = os.path.expanduser(self.framework_config_get("OUTPUT_PATH"))
        if not os.path.isabs(output_dir) and directory_access(os.getcwd(), "w+"):
            return output_dir
        else:
            # The output_dir may not be created yet, so check its parent.
            if directory_access(os.path.dirname(output_dir), "w+"):
                return output_dir
        return os.path.expanduser(os.path.join(self.framework_config_get("SETTINGS_DIR"), output_dir))

    def get_output_dir_targets(self):
        return os.path.join(self.get_output_dir(), self.framework_config_get("TARGETS_DIR"))

    def clean_up_target_dir(self, target_URL):
        return FileOperations.rm_tree(self.get_output_dir_targets(target_URL))

    def get_output_dir_target(self, target_URL):
        clean_target_URL = target_URL.replace("/", "_").replace(":", "").replace("#", "")
        return os.path.join(self.get_output_dir_targets(), clean_target_URL)

    def create_output_dir_for_target(self, target_URL):
        FileOperations.create_missing_dirs(self.get_output_dir_target(target_URL))
