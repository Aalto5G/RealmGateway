import logging
import yaml
import pprint
import os
from contextlib import suppress

from aalto_helpers import utils3
from loglevel import LOGLEVEL_DATAREPOSITORY

SUBSCRIBER_ID='SUBSCRIBER_ID'
SUBSCRIBER_SERVICES='SUBSCRIBER_SERVICES'


class DataRepository(object):
    def __init__(self, name='DataRepository', **kwargs):
        """ Initialize """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_DATAREPOSITORY)
        self.configfile = None
        self.configfolder = None
        self._loaded_data = None
        utils3.set_attributes(self, override=True, **kwargs)
        self.reload_data()

    def reload_data(self):
        self._load_data()

    def _load_data(self):
        # Load configuration data from config file
        d_file = self._load_data_file(self.configfile)
        d_folder = self._load_data_folder(self.configfolder)
        self._loaded_data = {**d_file, **d_folder}

    def _get_data(self):
        return dict(self._loaded_data)

    def _load_data_file(self, filename):
        # Load configuration from a single file
        data_d = {}
        try:
            data_d = yaml.load(open(filename,'r'))
        except FileNotFoundError:
            self._logger.warning('Repository file not found <{}>'.format(filename))
        except:
            self._logger.warning('Failed to load repository file <{}>'.format(filename))
        finally:
            return data_d

    def _load_data_folder(self, foldername):
        # Load configuration data from folder. Process only yaml files
        data_d = {}
        cwd = os.getcwd()
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

    def get_subscriber(self, subscriber_id, default = None):
        try:
            return self._get_data()[subscriber_id]
        except KeyError as e:
            self._logger.warning('No data for subscriber <{}>'.format(subscriber_id))
            return default

    def getall_subscriber(self, default = None):
        try:
            return self._get_data()
        except Exception as e:
            self._logger.warning('No data found for subscribers: {}'.format(e))
            return default

    def get_subscriber_service(self, subscriber_id, service_id, default = None):
        try:
            return self._get_data()[subscriber_id][service_id]
        except KeyError as e:
            self._logger.warning('No service <{}> for subscriber <{}>'.format(service_id, subscriber_id))
            return default

    def generate_default_subscriber(self, fqdn, ipv4):
        data_d = {}
        data_d['ID'] = {'FQDN':fqdn, 'IPV4':ipv4}
        sfqdn_services = []
        for token, proxy in (('',False), ('www.',True), ('sip',True)):
            sfqdn_services.append({'fqdn':'{}{}'.format(token, fqdn),
                                   'carriergrade': False,
                                   'proxy_required': proxy})
        data_d['SFQDN'] = sfqdn_services
        data_d['CIRCULARPOOL'] = [{'max':100}]
        return data_d

    '''
    def _getall_subscriber_service(self, subscriber_id, service_id):
        servicedata = {}
        raw_data = self._get_subscriber_data(subscriber_id)

        for usr_id, srv_data in data.items():
                if service_id in srv_data:
                    userdata[usr_id] = {service_id: srv_data[service_id]}

        data_all = yaml.load(open(self.servicedata,'r'))
        data = data_all[SUBSCRIBER_SERVICES]
        if subscriber_id and service_id:
            # Return data for subscriber_id
            return data[subscriber_id][service_id]
        elif subscriber_id:
            # Return specific service_id for subscriber_id
            return data[subscriber_id]
        elif service_id:
            # Return data for specific service_id
            userdata = {}
            for usr_id, srv_data in data.items():
                if service_id in srv_data:
                    userdata[usr_id] = {service_id: srv_data[service_id]}
            return userdata
        else:
            # Return data for all services
            return data
    '''

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
