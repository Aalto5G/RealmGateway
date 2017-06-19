import asyncio
import logging
import yaml
import pprint
import os
import urllib.parse
from contextlib import suppress

from aalto_helpers import utils3
from aiohttp_client import HTTPRestClient
from aiohttp_client import HTTPClientConnectorError


class DataRepository(object):
    def __init__(self, name='DataRepository', **kwargs):
        """ Initialize """
        self._logger = logging.getLogger(name)
        self.configfile = None
        self.configfolder = None
        self.policyfile = None
        self.policyfolder = None
        self.api_url = None
        utils3.set_attributes(self, override=True, **kwargs)
        self._cached_policy_host = None
        self._cached_policy_ces = None
        self._reload_policies()
        # Initiate HTTP session with PolicyDatabase
        self.rest_api_init()

    def rest_api_init(self, n=5):
        """ Create long lived HTTP session """
        self.rest_api = HTTPRestClient(n)

    def rest_api_close(self):
        self.rest_api.close()

    def _reload_policies(self):
        self._reload_policy_host()
        self._reload_policy_ces()

    def _reload_policy_host(self):
        # Load from file
        self._logger.info('Loading HOST POLICIES from file   <{}>'.format(self.configfile))
        d_file = self._load_data_file(self.configfile)
        # Load from folder
        self._logger.info('Loading HOST POLICIES from folder <{}>'.format(self.configfolder))
        d_folder = self._load_data_folder(self.configfolder)
        # Folder overrides single policy file definitions
        self._cached_policy_host = {**d_file, **d_folder}

    def _reload_policy_ces(self):
        # Load from file
        self._logger.info('Loading CES POLICIES from file   <{}>'.format(self.policyfile))
        d_file = self._load_data_file(self.policyfile)
        # Load from folder
        self._logger.info('Loading CES POLICIES from folder <{}>'.format(self.policyfolder))
        d_folder = self._load_data_folder(self.policyfolder)
        # Folder overrides single policy file definitions
        self._cached_policy_ces = {**d_file, **d_folder}

    def _load_data_file(self, filename):
        # Load configuration from a single file
        if not filename:
            return {}
        data_d = {}
        try:
            self._logger.debug('Loading file <{}>'.format(filename))
            data_d = yaml.load(open(filename,'r'))
        except FileNotFoundError:
            self._logger.warning('Repository file not found <{}>'.format(filename))
        except:
            self._logger.warning('Failed to load repository file <{}>'.format(filename))
        finally:
            return data_d

    def _load_data_folder(self, foldername):
        # Load configuration data from folder. Process only yaml files
        if not foldername:
            return {}
        data_d = {}
        try:
            for filename in os.listdir(foldername):
                if not filename.endswith('.yaml'):
                    continue
                path_filename = os.path.join(os.getcwd(), foldername, filename)
                d = self._load_data_file(path_filename)
                data_d = {**data_d, **d}
        except:
            self._logger.warning('Failed to load repository folder <{}>'.format(foldername))
        finally:
            return data_d

    def _get_policy_host(self):
        return dict(self._cached_policy_host)

    def _get_policy_ces(self):
        return dict(self._cached_policy_ces)

    def get_policy_ces(self, policy_id, default = None):
        try:
            return self._get_policy_ces()[policy_id]
        except KeyError as e:
            self._logger.warning('No data for policy <{}>'.format(policy_id))
            return default

    @asyncio.coroutine
    def get_policy_host(self, subscriber_id, default = None):
        try:
            return self._get_policy_host()[subscriber_id]
        except KeyError as e:
            self._logger.warning('No data for subscriber <{}>'.format(subscriber_id))
            return default

    def get_policy_host_all(self, default = None):
        try:
            return self._get_policy_host()
        except Exception as e:
            self._logger.warning('No data found for subscribers: {}'.format(e))
            return default

    @asyncio.coroutine
    def get_policy_host_default(self, fqdn, ipv4):
        data_d = {}
        data_d['ID'] = {'fqdn':fqdn, 'ipv4':ipv4}
        sfqdn_services = []
        for token, proxy in (('',False), ('www.',True), ('sip',True)):
            sfqdn_services.append({'fqdn':'{}{}'.format(token, fqdn),
                                   'carriergrade': False,
                                   'proxy_required': proxy})
        data_d['SFQDN'] = sfqdn_services
        data_d['CIRCULARPOOL'] = [{'max':2}]
        data_d['GROUP'] = ['IPS_GROUP_PREPAID1']
        return data_d
