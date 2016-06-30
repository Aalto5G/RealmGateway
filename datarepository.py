import logging
import utils
import yaml
import pprint

LOGLEVELDATAREPOSITORY = logging.WARNING


class DataRepository(object):
    def __init__(self, name='DataRepository', **kwargs):
        """ Initialize """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELDATAREPOSITORY)
        attrlist = ['url','file','subscriberdata','servicedata','policydata']
        utils.set_default_attributes(self, attrlist, None)
        utils.set_attributes(self, **kwargs)

    def get_subscriber_data(self, subscriber_id):
        return self._get_subscriber_data(subscriber_id)

    def get_subscriber_service(self, subscriber_id, service_id):
        return self._get_subscriber_service(subscriber_id, service_id)

    def _get_subscriber_data(self, subscriber_id):
        data_all = yaml.load(open(self.subscriberdata,'r'))
        data = data_all['SUBSCRIBER_ID']
        if not subscriber_id:
            return data
        return data[subscriber_id]

    def _get_subscriber_services(self, service_id = None):
        subscriberdata_d = yaml.load(open(self.servicedata,'r'))
        if service_id:
            return subscriberdata_d['SUBSCRIBER_SERVICES'][service_id]
        else:
            return subscriberdata_d['SUBSCRIBER_SERVICES']

    def _get_subscriber_service(self, subscriber_id, service_id):
        data_all = yaml.load(open(self.servicedata,'r'))
        data = data_all['SUBSCRIBER_SERVICES']
        if not subscriber_id and not service_id:
            # Return all data
            return data
        elif not subscriber_id and service_id:
            # Return service_id for all subscribers
            return data[service_id]
        elif not service_id and subscriber_id:
            # Return all services for subscriber_id
            userdata = {}
            for k,v in data.items():
                # Copy key/value to dictionary
                userdata[k] = v[subscriber_id]
            return userdata
        elif service_id and subscriber_id:
            # Return service_id for subscriber_id
            return data[service_id][subscriber_id]

if __name__ == "__main__":
    file = 'hosts_rgw.yaml'
    repo = DataRepository(subscriberdata=file, servicedata=file, policydata=file)
    print('\nGet all subscriber_data')
    pprint.pprint(repo.get_subscriber_data(None))
    print('\nGet all subscriber_data(foo100.rgw.)')
    pprint.pprint(repo.get_subscriber_data('foo100.rgw.'))
    print('\nGet all subscriber_service')
    pprint.pprint(repo.get_subscriber_service(None,None))
    print('\nGet all subscriber_service(foo100.rgw., SFQDN)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.','SFQDN'))
    print('\nGet all subscriber_service(foo100.rgw., FIREWALL)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.','FIREWALL'))
    print('\nGet all subscriber_service(foo100.rgw., None)')
    pprint.pprint(repo.get_subscriber_service('foo100.rgw.',None))
