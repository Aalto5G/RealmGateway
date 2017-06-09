import logging
import yaml
import pprint
import os
from contextlib import suppress

from aalto_helpers import utils3
from aiohttp_client import HTTPRestClient
from aiohttp_client import HTTPClientConnectorError
from loglevel import LOGLEVEL_DATAREPOSITORY


class DataRepository(object):
    def __init__(self, name='DataRepository', **kwargs):
        """ Initialize """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_DATAREPOSITORY)
        self.configfile = None
        self.configfolder = None
        self.policyfile = None
        self.policyfolder = None
        self.api_url = None
        utils3.set_attributes(self, override=True, **kwargs)
        self._loaded_data_subscriber = None
        self._loaded_data_policy = None
        self.reload_data()
        # Initiate HTTP session with PolicyDatabase
        self.rest_api_init()

    def rest_api_init(self, n=5):
        """ Create long lived HTTP session """
        self.rest_api = HTTPRestClient(n)

    def rest_api_close(self):
        self.rest_api.close()

    def reload_data(self):
        self._load_data_subscriber()
        self._load_data_policy()

    def _load_data_subscriber(self):
        # Load configuration data from config file
        self._logger.info('Loading subscriber data from file   <{}>'.format(self.configfile))
        d_file = self._load_data_file(self.configfile)
        self._logger.info('Loading subscriber data from folder <{}>'.format(self.configfolder))
        d_folder = self._load_data_folder(self.configfolder)
        # Subscriber folder overrides subscriber file definitions
        self._loaded_data_subscriber = {**d_file, **d_folder}

    def _load_data_policy(self):
        # Load configuration data from config file
        self._logger.info('Loading policy data from file   <{}>'.format(self.policyfile))
        d_file = self._load_data_file(self.policyfile)
        self._logger.info('Loading policy data from folder <{}>'.format(self.policyfolder))
        d_folder = self._load_data_folder(self.policyfolder)
        # Policy folder overrides policy file definitions
        self._loaded_data_policy = {**d_file, **d_folder}

    def _get_subscriber_data(self):
        return dict(self._loaded_data_subscriber)

    def _get_policy_data(self):
        return dict(self._loaded_data_policy)

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

    def get_policy(self, policy_id, default = None):
        try:
            return self._get_policy_data()[policy_id]
        except KeyError as e:
            self._logger.warning('No data for policy <{}>'.format(policy_id))
            return default

    def get_subscriber(self, subscriber_id, default = None):
        try:
            return self._get_subscriber_data()[subscriber_id]
        except KeyError as e:
            self._logger.warning('No data for subscriber <{}>'.format(subscriber_id))
            return default

    def getall_subscriber(self, default = None):
        try:
            return self._get_subscriber_data()
        except Exception as e:
            self._logger.warning('No data found for subscribers: {}'.format(e))
            return default

    def get_subscriber_service(self, subscriber_id, service_id, default = None):
        try:
            return self._get_subscriber_data()[subscriber_id][service_id]
        except KeyError as e:
            self._logger.warning('No service <{}> for subscriber <{}>'.format(service_id, subscriber_id))
            return default

    def generate_default_subscriber(self, fqdn, ipv4):
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


if __name__ == "__main__":
    configfile = 'gwa.demo.datarepository.yaml'
    configfolder = None
    repo = DataRepository(configfile = configfile, configfolder = configfolder)
    print('\nGet all subscriber_data')
    pprint.pprint(repo.get_subscriber(None))
    print('\nGet all subscriber_data(foo100.rgw.)')
    pprint.pprint(repo.get_subscriber('foo100.rgw.'))
    print('\nGet all subscriber_service(None,None)')
    pprint.pprint(repo.get_subscriber_service(None,None))
    print('\nGet subscriber_service(foo100.rgw., SFQDN)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.','SFQDN'))
    print('\nGet subscriber_service(foo100.rgw., FIREWALL)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.','FIREWALL'))
    print('\nGet subscriber_service(foo100.rgw., None)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.',None))
    print('\nGet subscriber_service(None, CIRCULARPOOL)')
    pprint.pprint(repo.get_subscriber_service(None,'CIRCULARPOOL'))
    print('\nGet subscriber_service(None, SFQDN)')
    pprint.pprint(repo.get_subscriber_service(None,'SFQDN'))
    print('\nGet subscriber_service(nonexist.rgw., None)')
    pprint.pprint(repo.get_subscriber_service('nonexist.rgw.', None))
    print('\nGet subscriber_service(foo100.rgw., nonexist)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.', 'nonexist'))
