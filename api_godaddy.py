import os
import requests


GODADDY_API_KEY = os.getenv("GODADDY_API_KEY")
GODADDY_SECRET = os.getenv("GODADDY_SECRET")
API_ENDPOINT_URL = "https://api.godaddy.com/v1/domains"
API_ENDPOINT_URL_RECORDS = API_ENDPOINT_URL + "/rport.io/records/A"
SCW_HEADERS = {"Authorization": "sso-key %s:%s" % (GODADDY_API_KEY, GODADDY_SECRET),
               "accept": "application/json"}


class ApiGoDaddy:
    """
    GoDaddy API
    https://developer.godaddy.com/
    """

    def __init__(self, logger):
        self.logger = logger

    def delete_record(self, record_name):

        """
        Deletes a record
        """

        response = requests.delete(API_ENDPOINT_URL_RECORDS + "/" + record_name,
                                   headers=SCW_HEADERS)
        if response.status_code == 204:
            self.logger.info("Record deleted successfully: %s", response.status_code)
        else:
            self.logger.error(response)
