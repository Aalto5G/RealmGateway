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
        ''' Return a dictionary where
        key = FQDN of the subscriber
        value = Dictionary with the subscriber data
        {'foo100.rgw.': {'fqdn': 'foo100.rgw.', 'ipv4': '192.168.0.100', 'msisdn': '0000000101'}}
        '''
        return self._get_subscriber_data(subscriber_id)

    def get_subscriber_service(self, subscriber_id, service_id):
        ''' Return a dictionary where
        keys = FQDN of the subscribers
        value = Dictionary with the subscriber data and registered services
        {'foo100.rgw.': {'CIRCULARPOOL': [{'max': 3}],
                         'FIREWALL': [{'action': 'ACCEPT', ...}]}}
        '''
        return self._get_subscriber_service(subscriber_id, service_id)

    def _get_subscriber_data(self, subscriber_id):
        data_all = yaml.load(open(self.subscriberdata,'r'))
        data = data_all[SUBSCRIBER_ID]
        if not subscriber_id:
            return data
        return data[subscriber_id]

    def _get_subscriber_service(self, subscriber_id, service_id):
        data_all = yaml.load(open(self.servicedata,'r'))
        data = data_all[SUBSCRIBER_SERVICES]
        userdata = {}
        
        if subscriber_id is not None:
            # Get data for subscriber_id
            userdata[subscriber_id] = {}
            if service_id is not None:
                # Return specific service_id for subscriber_id
                userdata[subscriber_id][service_id] = data[service_id][subscriber_id]
            else:
                # Iterate all services for subscriber_id                  
                for k,v in data.items():
                    if subscriber_id not in v:
                        continue
                    userdata[subscriber_id][k] = v[subscriber_id]
        elif subscriber_id is None:
            # Not supported - return empty dictionary
            if service_id is not None:
                # Get data for specific service_id
                for k,v in data[service_id].items():
                    userdata[k] = {service_id: v}
            else:
                # Get data for all services
                for k,v in data.items():
                    for _k,_v in v.items():
                        userdata.setdefault(_k, {})
                        userdata[_k][k] = _v
        return userdata
        

if __name__ == "__main__":
    file = 'datarepository.yaml'
    repo = DataRepository(subscriberdata=file, servicedata=file, policydata=file)
    print('\nGet all subscriber_data')
    pprint.pprint(repo.get_subscriber_data(None))
    print('\nGet all subscriber_data(foo100.rgw.)')
    pprint.pprint(repo.get_subscriber_data('foo100.rgw.'))
    print('\nGet all subscriber_service')
    pprint.pprint(repo.get_subscriber_service(None,None))
    print('\nGet subscriber_service(foo100.rgw., SFQDN)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.','SFQDN'))
    print('\nGet subscriber_service(foo100.rgw., FIREWALL)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.','FIREWALL'))
    print('\nGet subscriber_service(foo100.rgw., None)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.',None))
    print('\nGet subscriber_service(None, CIRCULARPOOL)')
    pprint.pprint(repo.get_subscriber_service(None,'CIRCULARPOOL'))
