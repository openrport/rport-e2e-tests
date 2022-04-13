import os
import sys
import time
import requests
from helper import Helper

SCW_INSTANCE_ZONE = "https://api.scaleway.com/instance/v1/zones/fr-par-1"
SCW_HEADERS = {"X-Auth-Token": os.getenv("SCALEWAY_SECRET_KEY"), "Content-Type": "application/json"}
SCW_COMPUTE_API_URL = SCW_INSTANCE_ZONE + "servers"
SCW_VOLUME_API_URL = SCW_INSTANCE_ZONE + "volumes"
SCW_LIST_SERVERS_API_URL = SCW_INSTANCE_ZONE + "/products/servers"
SCW_LIST_INSTANCE_IMAGES_API_URL = SCW_INSTANCE_ZONE + "/images"
INSTANCE_TYPE = "DEV1-S"
IMAGE_ID = "f0820d55-d708-4db5-8c43-368078f1e350"
PROJECT_ID = 'acf000f6-14f0-490f-a303-6f67a1015a8d'


def get_status(server_id):
    """
    Gets scaleway server state
    """
    response = requests.get(SCW_COMPUTE_API_URL + "/" + server_id, headers=SCW_HEADERS)
    state = response.json()
    return state['server']['state']


class ApiScaleway:

    """
    Scaleway API
    https://www.scaleway.com/en/api/
    """

    def __init__(self, logger):
        self.logger = logger
        self.helper = Helper(logger)
        self.volume_id = None

    def delete_server(self, server_id, with_volume=True):

        """
        Deletes running or powered off server
        """

        # make sure its powered off
        self.logger.info("Stopping server")
        action_payload = {"action": "poweroff"}
        requests.post(SCW_COMPUTE_API_URL + "/" + server_id + "/action",
                      json=action_payload, headers=SCW_HEADERS)

        count = 0
        sys.stdout.write("[INFO] ")
        sys.stdout.flush()

        server_state = get_status(server_id)
        while server_state != "stopped":
            if count > 120:
                self.delete_server(server_id)
                self.logger.error("timed out while waiting for server to stop")
                return {"message": "error",
                        "description": "timed out while waiting for server to stop"}
            count += 1

            sys.stdout.write(".")
            sys.stdout.flush()

            time.sleep(2)
            server_state = get_status(server_id)

        sys.stdout.write("ok\n")
        sys.stdout.flush()

        # delete now
        r_delete = requests.delete(SCW_COMPUTE_API_URL + "/" + server_id, headers=SCW_HEADERS)
        if r_delete.status_code == 204:
            self.logger.info("Server deleted successfully: %s", r_delete.status_code)
        else:
            self.logger.error(r_delete)
            return r_delete

        if with_volume:
            self.logger.info("Delete volume id: %s", self.volume_id)

            r_delete = requests.delete(SCW_VOLUME_API_URL + "/" + self.volume_id,
                                       headers=SCW_HEADERS)
            if r_delete.status_code == 204:
                self.logger.info("Volume deleted successfully: %s", r_delete.status_code)
            else:
                self.logger.error(r_delete)
                return r_delete

    def create_server(self, power_on=True):

        """
        Creates a new server
        """

        server_name = "e2e" + self.helper.get_random_string(15)
        payload = {
            "name": server_name,
            "commercial_type": INSTANCE_TYPE,
            "image": IMAGE_ID,
            "volumes": {},
            "project": PROJECT_ID
        }

        self.logger.info("Creating server")
        r_create = requests.post(SCW_COMPUTE_API_URL, json=payload, headers=SCW_HEADERS)

        self.volume_id = r_create.json()['server']['volumes']['0']['id']
        server_id = r_create.json()["server"]["id"]

        self.logger.info("Server created id: %s, with name: %s", server_id, server_name)

        if power_on:
            action_payload = {"action": "poweron"}

            requests.post(SCW_COMPUTE_API_URL + "/" + server_id + "/action",
                          json=action_payload,
                          headers=SCW_HEADERS)

            server_state = get_status(server_id)
            self.logger.info("Waiting for server to become ready")

            count = 0
            sys.stdout.write("[INFO] ")
            sys.stdout.flush()

            while server_state != "running":
                if count > 90:
                    self.delete_server(server_id)
                    self.logger.error("Task timed out while waiting for server to boot")
                    return {"message": "error",
                            "description": "timed out while waiting for server to boot"}
                count += 1

                sys.stdout.write(".")
                sys.stdout.flush()

                time.sleep(2)
                server_state = get_status(server_id)

            sys.stdout.write("ok\n")
            sys.stdout.flush()

            r_server = requests.get(SCW_COMPUTE_API_URL + "/" + server_id,
                                    headers=SCW_HEADERS)
            return r_server.json()
