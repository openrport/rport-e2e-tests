import os
import sys
import logging.config
import argparse
import time
from configparser import ConfigParser
import pyotp
import paramiko
import requests
from requests.auth import HTTPBasicAuth
from api_scaleway import ApiScaleway
from api_godaddy import ApiGoDaddy
from helper import Helper


LOGGING_CONFIG = {
    'formatters': {
        'brief': {
            'format': '[%(asctime)s][%(levelname)s] %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'rotating_file_handler': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'brief',
            'filename': 'e2e.log',
            'maxBytes': 1024*1024,
            'backupCount': 1,
        }
    },
    'loggers': {
        'main': {
            'propagate': False,
            'handlers': ['console', 'rotating_file_handler'],
            'level': 'INFO'
        }
    },
    'version': 1
}

SSH_PATH = os.getenv("SSH_PATH")
AUTH_INSTALLER = os.getenv("AUTH_INSTALLER")
SSH_PWD = os.getenv("SSH_PWD")
PAIRING_URL = "https://pairing.rport.io/"
CWD = os.path.dirname(os.path.realpath(__file__))
CONFIG_PATH = os.path.join(CWD, "rport.cfg")


class Master:

    """
    Executes various API tests on rport
    having tot2fa enabled
    and returns a test summary
    """

    def __init__(self, logger, args_in):
        self.logger = logger
        self.args = args_in

        # store script results for summary
        self.summary = {
            'log-in': "undefined",
            'failures': []
        }

    def process(self):

        """
        Creates a server on scaleway with totp2fa
        Runs various API tests and returns a summary
        """

        server_id = None
        rport_details = None
        secret = None
        ip_address = None

        scaleway = ApiScaleway(self.logger)
        parser_conf = ConfigParser()
        godaddy = ApiGoDaddy(self.logger)

        parser_conf.read(CONFIG_PATH)

        try:
            # -----------------------------------------------------------
            # ++++ create server on scaleway
            # -----------------------------------------------------------
            server = scaleway.create_server()
            ip_address = server['server']['public_ip']['address']
            server_id = server['server']['id']

            ssh_client = paramiko.SSHClient()
            my_pkey = paramiko.RSAKey.from_private_key_file(SSH_PATH, password=SSH_PWD)
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info("Connecting to: %s", ip_address)

            err = "error not provided!"
            for _ in range(90):
                try:
                    ssh_client.connect(hostname=ip_address, username="root", pkey=my_pkey)
                    sys.stdout.write("ok\n")
                    sys.stdout.flush()
                    break
                except Exception:
                    sys.stdout.write(".")
                    sys.stdout.flush()
                    time.sleep(1)
            else:
                self.logger.error("Couldn't connect to the SSH Server: %s", err)
                raise Exception("Couldn't connect to the SSH Server: %s" % err)

            self.logger.info("Connected to: %s", ip_address)

            # download rport server installer
            command = "apt-get update --allow-releaseinfo-change"
            self.exec_command(ssh_client, command)

            if self.args.auth_installer:
                command = "curl -u %s -o installer.sh https://get.rport.io &&" \
                          " bash installer.sh -h" % AUTH_INSTALLER
            else:
                command = "curl -o installer.sh https://get.rport.io &&" \
                          " bash installer.sh -h"
            self.exec_command(ssh_client, command)

            # install rport server
            if self.args.unstable:
                command = "bash installer.sh -t -o"
            else:
                command = "bash installer.sh -o"
            out = self.exec_command(ssh_client, command)

            # get server details: url, user and password
            helper = Helper(self.logger)
            rport_details = helper.get_match_from_output(out)

            # get rportd version
            command = "rportd --version"
            self.summary['version'] = self.exec_command(ssh_client, command).strip("\n")

            # -----------------------------------------------------------
            # ++++ login
            # GET {{rporturl}}/api/v1/login
            # POST {{rporturl}}/api/v1/me/totp-secret
            # POST {{rporturl}}/api/v1/verify-2fa
            # -----------------------------------------------------------
            r_login = requests.get(rport_details['url'] + "/api/v1/login",
                                   auth=HTTPBasicAuth(rport_details['user'],
                                                      rport_details['password']))
            login = r_login.json()
            self.summary['log-in'] = self.has_no_errors(login)

            # read secret key
            auth_header = {"Authorization": "Bearer " + login["data"]["token"]}
            secret = requests.post(rport_details['url'] + "/api/v1/me/totp-secret",
                                   headers=auth_header).json()
            self.has_no_errors(secret)

            # verify totp 2fa
            totp = pyotp.TOTP(secret['secret'])

            payload = {"username": "admin", "token": totp.now()}
            r_verify = requests.post(rport_details['url'] + "/api/v1/verify-2fa",
                                     json=payload,
                                     headers=auth_header)
            verify = r_verify.json()
            self.summary['log-in'] = self.has_no_errors(verify)

            # -----------------------------------------------------------
            # ++++ create a script
            # to make sure totp token works
            # -----------------------------------------------------------

            payload = {
                "name": "current_directory",
                "interpreter": "cmd",
                "is_sudo": True,
                "cwd": "/home",
                "script": "pwd"
            }
            auth_header = {"Authorization": "Bearer " + verify["data"]["token"]}
            create_script = requests.post(rport_details['url'] + "/api/v1/library/scripts",
                                          json=payload,
                                          headers=auth_header).json()
            self.summary['create-script'] = self.has_no_errors(create_script)

            if create_script['data']['name'] != "current_directory":
                self.logger.error("create script: %s", create_script['data'])
                raise Exception("create script failed")

            # -----------------------------------------------------------
            # ++++ status
            # -----------------------------------------------------------

            status = requests.get(rport_details['url'] + "/api/v1/status",
                                  headers=auth_header).json()
            self.has_no_errors(status)
            if status['data']['two_fa_delivery_method'] != 'totp_authenticator_app':
                self.logger.error("create script: %s", status)
                raise Exception("status failed")

        except Exception as error:
            self.logger.error("Test failed with the following error: %s", error)
            self.summary['failures'].append(error)
            raise

        finally:

            if not self.summary['failures']:
                self.logger.debug("---------  Details  --------------")
                self.logger.debug("TOTP secret: %s", secret['secret'])
                self.logger.debug("totp = pyotp.TOTP('%s')", secret['secret'])
                self.logger.debug("Public server IP: %s", ip_address)
                self.logger.debug("Rport server url: %s", rport_details['url'])
                self.logger.debug("User and password: %s, %s", rport_details['user'],
                                  rport_details['password'])
                self.logger.debug("-----------------------------------")

            # -----------------------------------------------------------
            # ++++ Tear down server
            # -----------------------------------------------------------

            # delete scaleway server
            if server_id:
                delete = scaleway.delete_server(server_id)
                if delete is not None:
                    self.summary['failures'].append(delete)

            # delete godaddy record
            if rport_details.get('record'):
                godaddy.delete_record(rport_details['record'])  # format: '30xmycbinf42.users'

            # -----------------------------------------------------------
            # ++++ Summary
            # -----------------------------------------------------------

            self.logger.info("-----------------------------------")
            self.logger.info("---------  Summary  ---------------")
            self.logger.info("-----------------------------------")
            self.logger.info("Rport server version: %s", self.summary['version'])
            self.logger.info("API log in admin: %s", self.summary['log-in'])
            self.logger.info("-----------------------------------")

            if self.summary['failures']:
                self.logger.info("---------  Failures  --------------")
                self.logger.info("-----------------------------------")
                self.logger.info("---------  Total (%d)  ------------",
                                 len(self.summary['failures']))
                for failure in self.summary['failures']:
                    self.logger.error(failure)
                self.logger.info("-----------------------------------")
                raise Exception("Failures reported.")
            self.logger.info("No summary errors reported.")

    def exec_command(self, client, command):

        """
        executes commands on the rport server
        :param client:
        :param command:
        :return: stdout of the command executed
        """

        self.logger.info("Execute server command: %s. Be patient!", command)

        for _ in range(3):
            _, stdout, stderr = client.exec_command(command)
            err = stderr.read().decode()
            out = stdout.read().decode()

            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                self.logger.error(err)
            else:
                self.logger.info("Server command executed ok: %s" % command)
                break
        else:
            self.logger.error("Execute mandatory server command: %s failed!", command)
            raise Exception("Execute mandatory server command failed. See logs for details")

        self.logger.info(out)
        return out

    def exec_instance_command(self, instance, command):

        """
        Executes a command on an instance
        :param instance: instance object
        :param command: command to execute
        :return
        """

        stderr = None
        for _ in range(3):
            (exit_code, stdout, stderr) = instance.execute(command)
            if exit_code != 0:
                self.logger.warning("stderr: %s", stderr)
                self.logger.warning("stdout: %s", stdout)
                self.logger.info("Something went wrong while exec: %s Don't you worry,"
                                 " we re-try up to 3 attempts",
                                 command)
                time.sleep(3)
            else:
                self.logger.info("Instance command executed ok: %s" % command)
                if stdout:
                    self.logger.info(stdout)
                return stdout

        self.logger.error("Instance command failed: %s" % command)
        self.summary['failures'].append(stderr)
        return stderr

    def has_no_errors(self, response):

        """
        Checks if response has any errors
        :param response: response object
        :return:
        """

        if response.get("errors"):
            self.logger.error("Request exited with errors: %s", response)
            self.summary['failures'].append(response)
            return response
        self.logger.info("Request ok: %s", response)
        return "ok"

    def wait_for_instance_state(self, instance, state):

        """
        Waits until an instance has the required state
        :param instance: instance object
        :param state: required state
        :return:
        """

        self.logger.info("Wait for instance status: %s", state)
        for _ in range(60):
            self.logger.debug(instance.state().status)
            if instance.state().status == state:
                return
            time.sleep(5)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='rport-e2e')
    parser.add_argument('--logger', action="store", dest="logger", default="INFO")
    parser.add_argument('--unstable', action="store_true", dest="unstable")
    parser.add_argument('--auth-installer', action="store_true",
                        dest="auth_installer", default=True)
    args = parser.parse_args()

    print("[INFO] Logger: {}".format(args.logger))
    if args.unstable:
        print("[INFO] Running unstable release")
    else:
        print("[INFO] Running stable release")
    if args.auth_installer:
        print("[INFO] Server installer authenticated. Let's encrypt is not used.")
    logging.config.dictConfig(LOGGING_CONFIG)
    log = logging.getLogger('main')
    log.setLevel(level=logging.getLevelName(args.logger))

    master = Master(log, args)
    master.process()
