import logging
import utils
import yaml
import pprint

LOGLEVELDATAREPOSITORY = logging.WARNING

SUBSCRIBER_ID='SUBSCRIBER_ID'
SUBSCRIBER_SERVICES='SUBSCRIBER_SERVICES'

class DataRepository(object):
    def __init__(self, name='DataRepository', **kwargs):
        """ Initialize """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELDATAREPOSITORY)
        attrlist = ['url','file','subscriberdata','servicedata','policydata']
        utils.set_default_attributes(self, attrlist, None)
        utils.set_attributes(self, **kwargs)

    def get_subscriber_data(self, subscriber_id):
        try:
            return self._get_subscriber_data(subscriber_id)
        except KeyError as e:
            self._logger.warning('get_subscriber_data({}): KeyError {}'.format(subscriber_id, e))
            return {}

    def get_subscriber_service(self, subscriber_id, service_id):
        try:
            return self._get_subscriber_service(subscriber_id, service_id)
        except KeyError as e:
            self._logger.warning('get_subscriber_service({}, {}): KeyError {}'.format(subscriber_id, service_id, e))
            if not subscriber_id or not service_id:
                return {}
            else:
                return []

    def _get_subscriber_data(self, subscriber_id):
        data_all = yaml.load(open(self.subscriberdata,'r'))
        data = data_all[SUBSCRIBER_ID]
        if not subscriber_id:
            return data
        return data[subscriber_id]

    def _get_subscriber_service(self, subscriber_id, service_id):
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

if __name__ == "__main__":
    file = 'datarepository.yaml'
    repo = DataRepository(subscriberdata=file, servicedata=file, policydata=file)
    print('\nGet all subscriber_data')
    pprint.pprint(repo.get_subscriber_data(None))
    print('\nGet all subscriber_data(foo100.rgw.)')
    pprint.pprint(repo.get_subscriber_data('foo100.rgw.'))
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
