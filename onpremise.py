import os
import subprocess
import logging.config
import argparse
import time
from configparser import ConfigParser
from pylxd.exceptions import LXDAPIException
from pylxd import Client
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
    Installs on-premise rport
    and returns a test summary
    """

    def __init__(self, logger, args_in):
        self.logger = logger
        self.args = args_in

        # store script results for summary
        self.summary = {
            'version': [],
            'details': [],
            'failures': [],
        }

    def process(self):

        """
        Installs on-premise rport
        and returns a test summary
        """

        instances = {}

        images = ["ubuntu", "centos", "debian"]
        # images = ["centos"]

        parser_conf = ConfigParser()
        parser_conf.read(CONFIG_PATH)

        try:
            # -----------------------------------------------------------
            # ++++ is any client already running?
            # -----------------------------------------------------------

            client = Client()

            cis = client.instances.all()

            for ci in cis:
                if ci.name in images:
                    self.logger.error("Instance named %s is already running."
                                      " Please stop/delete all instances named: %s"
                                      " and start the script again", ci.name, images)
                    raise Exception("Instance named %s is already running."
                                    " Stop/delete all: %s" % (ci.name, images))

            for _, linux in enumerate(images):

                self.logger.info("Running linux flavor: %s", linux)

                fingerprint = os.getenv("%s_FINGERPRINT" % linux.upper())
                exec_script = parser_conf.get(linux, 'exec_script')
                prep_command = parser_conf.get(linux, 'prep_command')
                prep_command_server = parser_conf.get(linux, 'prep_command_server')

                self.logger.info("fingerprint: %s", fingerprint)
                self.logger.info("prep_command: %s", prep_command)
                self.logger.info("prep_command_server: %s", prep_command_server)

                config = {'name': linux, 'source': {'type': 'image', 'fingerprint': fingerprint}}

                try:
                    instance = client.instances.create(config, wait=True)
                except LXDAPIException as e:
                    self.logger.error(e)
                    self.logger.error("Please stop/delete instances named ubuntu, debian, centos"
                                      " if they exist by executing commands:"
                                      " lxc stop centos and lxc delete centos")
                    continue

                instance.start()
                instances[linux] = instance

                self.wait_for_instance_state(instance, "Running")

                if exec_script:
                    cmd = ["lxc", "file", "push", "./scripts/%s" % exec_script, "%s/root/" % linux]
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            check=True)
                    if result.stderr:
                        self.logger.error(result.stderr)
                    self.logger.info(result.stdout)

                    # run script
                    self.exec_instance_command(instances[linux], ["./%s" % exec_script])

                # update /etc/hosts
                exec_script = "hostEntry.sh"
                cmd = ["lxc", "file", "push", "./scripts/%s" % exec_script, "%s/root/" % linux]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        check=True)
                if result.stderr:
                    self.logger.error(result.stderr)
                self.logger.info(result.stdout)
                self.exec_instance_command(instances[linux], ["./%s" % exec_script])

                if prep_command:
                    self.logger.info("Prep commands: %s", prep_command)
                    for pc in prep_command.split(","):
                        self.exec_instance_command(instance, pc.split(" "))

                if prep_command_server:
                    self.logger.info("Prep commands to install server: %s", prep_command_server)
                    for pc in prep_command_server.split(","):
                        self.exec_instance_command(instance, pc.split(" "))

                # install server command
                if self.args.auth_installer:
                    command = "curl -u %s -o installer.sh https://get.rport.io" % AUTH_INSTALLER
                else:
                    command = "curl -o installer.sh https://get.rport.io"

                self.logger.info("Download server installer: %s", command)
                self.exec_instance_command(instance, command.split(" "))

                self.logger.info("Running server installer help: %s", command)
                command = "bash installer.sh -h"
                self.exec_instance_command(instance, command.split(" "))

                # install rport server
                email = parser_conf.get("gmail", 'email').\
                    replace("+", "+" + str(int(round(time.time() * 1000))))
                if self.args.unstable:
                    command = "bash installer.sh -t --client-port 8000 --api-port 5000" \
                              " --fqdn rport.localnet" \
                              " --port-range 20000-20050 --email " + email
                else:
                    command = "bash installer.sh --client-port 8000 --api-port 5000" \
                              " --fqdn rport.localnet" \
                              " --port-range 20000-20050 --email " + email

                self.logger.info("Running server installer: %s", command)
                stdout = self.exec_instance_command(instance, command.split(" "))

                # get server details: url, user and password
                helper = Helper(self.logger)
                server_details = helper.get_match_from_output(stdout, False)

                if server_details['url'] == 'https://rport.localnet:5000':
                    self.summary['details'].append(server_details)
                else:
                    self.summary['failures'].append(server_details)

                # get rportd version
                command = "rportd --version"
                self.summary['version'].append(self.exec_instance_command(instance,
                                                                          command.split(" ")))

            self.logger.info("Instance count: %s", len(instances))

        finally:

            # -----------------------------------------------------------
            # ++++ Tear down servers
            # -----------------------------------------------------------

            if instances:
                # stop all lxd instances
                for _, i in instances.items():
                    i.stop()
                    self.wait_for_instance_state(i, "Stopped")
                    self.logger.info("Instance %s stopped.", i.name)

                # delete all lxd instances
                for _, i in instances.items():
                    i.delete()
                    self.logger.info("Instance %s deleted.", i.name)

            # -----------------------------------------------------------
            # ++++ Summary
            # -----------------------------------------------------------

            self.logger.info("-----------------------------------")
            self.logger.info("---------  Summary  ---------------")
            self.logger.info("-----------------------------------")
            self.logger.info("Rport server version: %s", self.summary['version'])
            self.logger.info("Rport server details: %s", self.summary['details'])
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
        :return:
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
    parser.add_argument('--determinant', action="store", dest="determinant", default="ANY")
    parser.add_argument('--unstable', action="store_true", dest="unstable")
    parser.add_argument('--auth-installer', action="store_true", dest="auth_installer",
                        default=True)
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
