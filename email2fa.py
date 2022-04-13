import os
import sys
import subprocess
import logging.config
import argparse
import time
from configparser import ConfigParser
import json
import websocket
import paramiko
import requests
from pylxd.exceptions import LXDAPIException
from pylxd import Client
from requests.auth import HTTPBasicAuth
from api_scaleway import ApiScaleway
from api_godaddy import ApiGoDaddy
from helper import Helper
from gmail.api import ApiGmail


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
    having email2fa enabled
    and returns a test summary
    """

    def __init__(self, logger, args_in):
        self.logger = logger
        self.args = args_in

        # summary - test results
        self.summary = {
            'tunnels': [],
            'single-host': [],
            'client-ids': [],
            'ssh-connected-clients': [],
            'log-in': "undefined",
            'create-script': "undefined",
            'log-in-new-user': "undefined",
            'client-kernel': [],
            'version': "undefined",
            'create-user': "undefined",
            'clients-auth': "undefined",
            'multi-hosts': [],
            'tacoscript': [],
            'me-token': "undefined",
            'single-host-script': [],
            'single-host-script-shebang': [],
            'failures': []
        }

    def process(self):

        """
        Creates a server on scaleway and connects 3 clients with it.
        Runs various API tests and returns a summary
        """

        server_id = None
        rport_details = {}
        instances = {}

        images = ["ubuntu", "centos", "debian"]
        # images = ["centos"]

        scaleway = ApiScaleway(self.logger)
        parser_conf = ConfigParser()
        godaddy = ApiGoDaddy(self.logger)

        parser_conf.read(CONFIG_PATH)

        try:
            # -----------------------------------------------------------
            # ++++ is any client already running?
            # -----------------------------------------------------------

            client = Client()

            cis = client.instances.all()

            for client_inst in cis:
                if client_inst.name in images:
                    self.logger.error("Instance named %s is already running."
                                      " Please stop/delete all instances named: %s"
                                      " and start the script again", client_inst.name, images)
                    raise Exception("Instance named %s is already running."
                                    " Stop/delete all: %s" % (client_inst.name, images))

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
                command = "curl -o installer.sh https://get.rport.io && bash installer.sh -h"
            self.exec_command(ssh_client, command)

            # delete all emails in inbox
            api = ApiGmail(self.logger)
            api.delete_all_emails()

            # install rport server
            email = parser_conf.get("gmail", 'email').\
                replace("+", "+" + str(int(round(time.time() * 1000))))
            if self.args.unstable:
                command = "bash installer.sh -t -e " + email
            else:
                command = "bash installer.sh -e " + email
            out = self.exec_command(ssh_client, command)

            # get server details: url, user and password
            helper = Helper(self.logger)
            rport_details = helper.get_match_from_output(out)

            # get rportd version
            command = "rportd --version"
            self.summary['version'] = self.exec_command(ssh_client, command).strip("\n")

            # generate pub and private e2e keys
            # add pub key to authorized_keys
            result = helper.run_command("genSshKeyPair.sh")
            if result.stderr:
                self.logger.error(result.stderr)
            self.logger.info(result.stdout)

            # -----------------------------------------------------------
            # ++++ login as admin
            # -----------------------------------------------------------
            r_login = requests.get(rport_details['url'] + "/api/v1/login",
                                   auth=HTTPBasicAuth(rport_details['user'],
                                                      rport_details['password']))
            login = r_login.json()
            self.summary['log-in'] = self.has_no_errors(login)

            # get 2fa token
            emails = api.get_emails_by_email(email)
            token_2fa = helper.get_2fa_code_match(emails[0]['content'])

            # verify 2fa
            payload = {"username": "admin", "token": token_2fa}
            auth_header = {"Authorization": "Bearer " + login["data"]["token"]}

            verify = requests.post(rport_details['url'] + "/api/v1/verify-2fa",
                                   json=payload,
                                   headers=auth_header).json()
            self.summary['log-in'] = self.has_no_errors(verify)

            # admin authorization bearer token
            # is used in all api calls from now on as authorization
            bearer_token = verify["data"]["token"]
            auth_header = {"Authorization": "Bearer " + bearer_token}

            # -----------------------------------------------------------
            # ++++ create a script
            # -----------------------------------------------------------

            payload = {
                "name": "current_directory",
                "interpreter": "cmd",
                "is_sudo": True,
                "cwd": "/home",
                "script": "pwd"
            }
            r_create_script = requests.post(rport_details['url'] + "/api/v1/library/scripts",
                                            json=payload,
                                            headers=auth_header)
            create_script = r_create_script.json()
            self.summary['create-script'] = self.has_no_errors(create_script)

            # -----------------------------------------------------------
            # ++++ create a new user
            # -----------------------------------------------------------
            username = "user1"
            password = "123456"
            payload = {
                "username": username,
                "password": password,
                "two_fa_send_to": email,
                "groups":
                    [
                        "Users",
                        "Administrators"
                    ]
            }
            self.summary['create-user'] = requests.post(rport_details['url'] + "/api/v1/users",
                                                        json=payload,
                                                        headers=auth_header).status_code
            # -----------------------------------------------------------
            # ++++ login as new user
            # -----------------------------------------------------------
            api.delete_all_emails()

            r_login = requests.get(rport_details['url'] + "/api/v1/login",
                                   auth=HTTPBasicAuth(username, password))
            login = r_login.json()
            self.summary['log-in-new-user'] = self.has_no_errors(login)

            # get 2fa token
            emails = api.get_emails_by_email(email)
            token_2fa = helper.get_2fa_code_match(emails[0]['content'])

            # verify 2fa
            payload = {"username": username, "token": token_2fa}
            auth_header_new_user = {"Authorization": "Bearer " + login["data"]["token"]}
            r_verify = requests.post(rport_details['url'] + "/api/v1/verify-2fa",
                                     json=payload,
                                     headers=auth_header_new_user)
            verify = r_verify.json()
            self.summary['log-in-new-user'] = self.has_no_errors(verify)

            auth_header_new_user = {"Authorization": "Bearer " + verify["data"]["token"]}

            # -----------------------------------------------------------
            # ++++ Personal API tokens
            # -----------------------------------------------------------
            # Permanent personal API token that is used in requests instead of temporary
            # bearer token
            # https://tracker.cloudradar.info/issue/DEV-2266

            r_token_me = requests.post(rport_details['url'] + "/api/v1/me/token",
                                       headers=auth_header_new_user)
            token_me = r_token_me.json()
            self.summary['me-token'] = self.has_no_errors(token_me)

            r_token_me = requests.get(rport_details['url'] + "/api/v1/me",
                                      auth=HTTPBasicAuth(username, token_me["data"]["token"]))
            token_me = r_token_me.json()
            self.has_no_errors(token_me)
            self.summary['me-token'] = token_me

            if token_me['data']['username'] != username:
                self.logger.error("/me endpoint failed: %s", token_me)
                self.summary['failures'].append(token_me)

            # -----------------------------------------------------------
            # ++++ Create instances, pairing clients with server
            # -----------------------------------------------------------

            for idx, linux in enumerate(images):

                self.logger.info("Running linux flavor: %s", linux)

                fingerprint = os.getenv("%s_FINGERPRINT" % linux.upper())
                exec_script = parser_conf.get(linux, 'exec_script')
                prep_command = parser_conf.get(linux, 'prep_command')
                prep_command_ssh = parser_conf.get(linux, 'prep_command_ssh')
                client_inst_args = parser_conf.get(linux, 'client_inst_args')

                self.logger.info("fingerprint: %s", fingerprint)
                self.logger.info("prep_command: %s", prep_command)
                self.logger.info("prep_command_ssh: %s", prep_command_ssh)
                self.logger.info("client_inst_args: %s", client_inst_args)

                r_clients_auth = requests.get(rport_details['url'] + "/api/v1/clients-auth",
                                              headers=auth_header)
                clients_auth = r_clients_auth.json()

                self.summary['clients-auth'] = self.has_no_errors(clients_auth)
                if self.summary['clients-auth'] != "ok":
                    continue

                if idx == 0:

                    # delete default access credentials
                    # create new ones

                    self.logger.info("Delete default access credentials, create new and use them")
                    caid = clients_auth['data'][0]['id']
                    r_delete = requests.delete(rport_details['url'] + "/api/v1/clients-auth/"
                                               + caid + "?force=false",
                                               headers=auth_header)
                    if r_delete.status_code != 204:
                        self.logger.error("/clients-auth delete failed, status_code: %s",
                                          r_delete.status_code)
                        self.summary['failures'].append(r_delete)
                        continue

                    payload = {"id": "rafaltest", "password": "wepE_Wd21y5IA-U"}
                    r_auth_post = requests.post(rport_details['url'] + "/api/v1/clients-auth",
                                                json=payload,
                                                headers=auth_header)

                    if r_auth_post.status_code != 201:
                        self.logger.error("/clients-auth post failed, status_code: %s",
                                          r_delete.status_code)
                        self.summary['failures'].append(r_auth_post)
                        continue

                    r_clients_auth = requests.get(rport_details['url'] + "/api/v1/clients-auth",
                                                  headers=auth_header)
                    clients_auth = r_clients_auth.json()

                    self.summary['clients-auth'] = self.has_no_errors(clients_auth)
                    if self.summary['clients-auth'] != "ok":
                        continue

                else:
                    self.logger.info("Use default client access credentials")

                r_status = requests.get(rport_details['url'] + "/api/v1/status",
                                        headers=auth_header)
                status = r_status.json()
                self.logger.info("status: %s", status)

                config = {'name': linux,
                          'source': {'type': 'image', 'fingerprint': fingerprint}}

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

                # pairing
                payload = {
                    "client_id": clients_auth['data'][0]['id'],
                    "connect_url": status['data']['connect_url'][0],
                    "fingerprint": status['data']['fingerprint'],
                    "password": clients_auth['data'][0]['password']
                }

                r_pairing = requests.post(PAIRING_URL, json=payload)
                pairing = r_pairing.json()

                if prep_command:
                    self.logger.info("Prep commands: %s", prep_command)
                    for p_c in prep_command.split(","):
                        self.exec_instance_command(instance, p_c.split(" "))

                self.logger.info("Pairing %s client: %s", linux, pairing)
                self.logger.info("Running client installer: rport-installer.sh %s",
                                 client_inst_args)

                commands = pairing['installers']['linux'].split("\n")
                if client_inst_args:
                    commands[1] += " "
                    commands[1] += client_inst_args
                if self.args.unstable:
                    commands[1] += " -t"
                    self.logger.info("Adding -t arg as testing unstable")
                exec_commands = [commands[0].split(" "), commands[1].split(" ")]
                for c in exec_commands:
                    self.exec_instance_command(instance, c)

                # to make sure port 22 SSH open
                if prep_command_ssh:
                    self.logger.info("Prep ssh commands: %s", prep_command_ssh)
                    for pcs in prep_command_ssh.split(","):
                        self.exec_instance_command(instance, pcs.split(" "))

            self.logger.info("Instance count: %s", len(instances))

            # -----------------------------------------------------------
            # get clients connected
            # patch level - https://tracker.cloudradar.info/issue/DEV-2218
            # -----------------------------------------------------------

            # Default fields that are returned are w/o updates.
            # You can specify additional fields using ?fields[clients]=updates_status
            r_clients = requests.get(rport_details['url'] + "/api/v1/clients?sort=name&"
                                                            "fields[clients]=updates_status",
                                     headers=auth_header)
            clients = r_clients.json()
            self.has_no_errors(clients)

            if clients["data"]:

                iteration_range = 30
                if self.args.determinant == "ANY":
                    iteration_range = 5

                # wait 30 minutes until clients have updates
                self.logger.info("-----------------------------------")
                self.logger.info("wait for updates on clients up to %s cycles", iteration_range)
                self.logger.info("-----------------------------------")
                for index in range(iteration_range):
                    results = []
                    for c in clients["data"]:
                        if c['updates_status']['update_summaries']:
                            self.logger.info("updates ok: update_summaries: %s",
                                             c['updates_status']['update_summaries'])
                            results.append(True)
                        else:
                            self.logger.info("no updates: (%d)", index)
                            results.append(False)

                    if self.args.determinant == "ALL" and all(results):
                        self.logger.info("Got updates on all clients")
                        break
                    if self.args.determinant == "ANY" and any(results):
                        self.logger.info("Got updates on any client(s)")
                        break
                    self.logger.debug("Did not get updates. Requesting again in 30 secs")
                    time.sleep(30)
                    r_clients = requests.get(rport_details['url'] +
                                             "/api/v1/clients?sort=name&"
                                             "fields[clients]=updates_status",
                                             headers=auth_header)
                    clients = r_clients.json()

                else:
                    self.logger.error("updates failed. See logs for more information")
                    self.summary['failures'].append("updates failed for determinant: %s"
                                                    % self.args.determinant)

                # get clients connected
                clients = requests.get(
                    rport_details['url'] + "/api/v1/clients?sort=name",
                    headers=auth_header).json()
                self.has_no_errors(clients)

                self.logger.info("-----------------------------------")

                # -----------------------------------------------------------
                # ++++ API get metrics
                # https://tracker.cloudradar.info/issue/DEV-2343
                # -----------------------------------------------------------

                self.logger.info("/metrics: wait up to %d cycles of 10 secs for metrics",
                                 iteration_range)

                for _ in range(iteration_range):
                    results = []
                    for c in clients["data"]:
                        metrics = requests.get(rport_details['url'] + "/api/v1/clients/"
                                               + c["id"] + "/metrics",
                                               headers=auth_header).json()
                        self.has_no_errors(metrics)
                        if not metrics['data']:
                            results.append(False)
                        elif metrics['data'] and metrics['data'][0]['io_usage_percent'] >= 0 \
                                and type(metrics['data'][0]['cpu_usage_percent']) == float:
                            results.append(True)
                        else:
                            results.append(False)

                    if self.args.determinant == "ALL" and all(results):
                        self.logger.info("Got metrics on ALL clients")
                        break
                    if self.args.determinant == "ANY" and any(results):
                        self.logger.info("Got metrics on ANY client(s)")
                        break
                    self.logger.debug("Did not get metrics, determinant: %s."
                                      " Requesting again in 10 secs",
                                      self.args.determinant)
                    time.sleep(10)

                else:
                    self.logger.error("metrics failed. See logs for more information")
                    self.summary['failures'].append("metrics failed for determinant: %s"
                                                    % self.args.determinant)

                # -----------------------------------------------------------
                # -----------------------------------------------------------

                for c in clients["data"]:

                    self.logger.info("Checking out %s client", c["hostname"])

                    # collect client ids
                    self.summary['client-ids'].append(c["id"])

                    # read rport status
                    self.exec_instance_command(instances[c["hostname"]],
                                               ["systemctl", "status", "rport"])

                    # -----------------------------------------------------------
                    # ++++ Allow commands and script execution on clients
                    # -----------------------------------------------------------

                    if parser_conf.get(c["hostname"], 'client_inst_args').count("-x"):
                        self.logger.info("Config already modified by -x argument")
                        # -x inserts:
                        # [remote-scripts]  enabled = true
                        #  allow = ['.*']
                    else:
                        # copy allowCommands.sh to instance /root
                        cmd = ["lxc", "file", "push", "./scripts/allowCommands.sh",
                               "%s/root/" % c["hostname"]]
                        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE, check=True)
                        if result.stderr:
                            self.logger.error(result.stderr)
                        self.logger.info(result.stdout)

                        # run script to update allowed commands in config
                        self.exec_instance_command(instances[c["hostname"]],
                                                   ["./allowCommands.sh"])

                        # restart rport client service
                        self.exec_instance_command(instances[c["hostname"]],
                                                   ["systemctl", "restart", "rport"])
                        self.exec_instance_command(instances[c["hostname"]],
                                                   ["systemctl", "status", "rport"])

                    # -----------------------------------------------------------
                    # ++++ Add pub key to authorized keys
                    # -----------------------------------------------------------
                    # create /root/.ssh folder
                    self.exec_instance_command(instances[c["hostname"]],
                                               ["mkdir", "-p", "/root/.ssh"])
                    self.exec_instance_command(instances[c["hostname"]],
                                               ["chmod", "700", "/root/.ssh"])

                    # copy authorized_keys to /root/.ssh
                    # set the owner
                    cmd = ["lxc", "file", "push", "./authorized_keys",
                           "%s/root/.ssh/" % c["hostname"]]
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            check=True)
                    if result.stderr:
                        self.logger.error(result.stderr)
                    self.logger.info(result.stdout)
                    self.exec_instance_command(instances[c["hostname"]],
                                               ["chown", "root:root", "/root/.ssh/authorized_keys"])

                    # -----------------------------------------------------------
                    # ++++ API get clients
                    # -----------------------------------------------------------

                    r_client = requests.get(rport_details['url'] + "/api/v1/clients/" + c["id"],
                                            headers=auth_header)
                    individual_client = r_client.json()

                    self.has_no_errors(individual_client)
                    if individual_client['data']['os_kernel'] != 'linux':
                        self.summary['client-kernel'].append(individual_client['data']['os_kernel'])
                        self.summary['failures'] = "Get clients/id misbehaved, os_kernel: %s" %\
                                                   individual_client['data']['os_kernel']

                    # -----------------------------------------------------------
                    # ++++ API create tunnels and test ssh connection via tunnels
                    # -----------------------------------------------------------
                    # create tunnel
                    if parser_conf.getboolean(c["hostname"], 'tunnel_autoclose'):
                        r_tunnel = requests.put(rport_details['url'] + "/api/v1/clients/"
                                                + c["id"] + "/tunnels?remote=22&auto-close=1m",
                                                headers=auth_header)
                    else:
                        r_tunnel = requests.put(rport_details['url'] + "/api/v1/clients/"
                                                + c["id"] + "/tunnels?remote=22",
                                                headers=auth_header)
                    tunnel = r_tunnel.json()

                    if self.has_no_errors(tunnel) == "ok":
                        self.summary['tunnels'].append(c["hostname"])

                        # turn off StrictHostKeyChecking
                        # trash all new discovered known hosts: -o UserKnownHostsFile=/dev/null
                        # cmd: ssh -o StrictHostKeyChecking=no -i e2e -p 20763
                        # -l root name.users.rport.io hostname
                        port_number = tunnel['data']['lport']
                        cmd = helper.run_command(["ssh", "-i", "e2e", "-o",
                                                  "StrictHostKeyChecking=no",
                                                  "-p", port_number, "-l", "root", "-o",
                                                  "UserKnownHostsFile=/dev/null",
                                                  rport_details['record'] + ".rport.io",
                                                  "hostname"], None, False)

                        if cmd.stderr:
                            self.logger.info(cmd.stderr)
                        self.logger.info("Test ssh connection: hostname: %s",
                                         cmd.stdout.decode("utf-8"))
                        self.summary['ssh-connected-clients'].append(cmd.stdout.decode("utf-8").
                                                                     strip("\n"))

                        if parser_conf.getboolean(c["hostname"], 'tunnel_autoclose'):
                            self.logger.info("Tunnel autoclose on, awaits 60 secs for auto-closure")
                            time.sleep(60)

                            # create again tunnel, this time w/o auto-close
                            tunnel = requests.put(rport_details['url'] + "/api/v1/clients/"
                                                  + c["id"] + "/tunnels?remote=22",
                                                  headers=auth_header).json()
                            self.has_no_errors(tunnel)

                    # -----------------------------------------------------------
                    # ++++ API create tunnels - UDP Service forwarding to snmp.tinyserver.net
                    # https://tracker.cloudradar.info/issue/DEV-2367
                    # -----------------------------------------------------------

                    udp_tunnel = requests.put(rport_details['url'] + "/api/v1/clients/"
                                              + c["id"] + "/tunnels?remote=snmp.tinyserver.net:161&"
                                                          "scheme=other&skip-idle-timeout=1&"
                                                          "protocol=udp",
                                              headers=auth_header).json()
                    if self.has_no_errors(udp_tunnel) == "ok":
                        exposed_port = udp_tunnel['data']['lport']

                        # snmpget -v 2c -c cloudr {rport-server}:{random-port} iso.3.6.1.2.1.1.6.0
                        # snmpget -v 2c -c cloudr test.users.rport.io:22992 iso.3.6.1.2.1.1.6.0
                        snmpget = helper.run_command(["snmpget", "-v", "2c", "-c", "cloudr",
                                                      rport_details['url'].
                                                     replace("443", exposed_port).
                                                     replace("https://", ""),
                                                      "iso.3.6.1.2.1.1.6.0"], None, False)

                        snmp_string = "Sitting on the Dock of the Bay"
                        if snmpget.stdout.decode("utf-8").strip("\n").count(snmp_string):
                            self.logger.info("Found 'Sitting on the Dock of the Bay' in cmd.stdout")
                        else:
                            self.logger.error("Failed to find '%s' in cmd.stdout: %s",
                                              snmp_string,
                                              snmpget.stdout.decode("utf-8").strip("\n"))
                            self.summary['failures'].append(snmpget.stdout.decode("utf-8").
                                                            strip("\n"))
                    else:
                        self.logger.error("snmpget not fired due to response with errors")

                    # -----------------------------------------------------------
                    # ++++ API create tunnels - built-in https proxys
                    # https://tracker.cloudradar.info/issue/DEV-2375
                    # -----------------------------------------------------------
                    r_tunnel = requests.put(rport_details['url'] + "/api/v1/clients/"
                                            + c["id"] + "/tunnels?remote=demo.ip-api.com:80&"
                                                        "scheme=http&idle-timeout-minutes=5&"
                                                        "http_proxy=true&"
                                                        "host_header=demo.ip-api.com",
                                            headers=auth_header)
                    tunnel = r_tunnel.json()
                    self.has_no_errors(tunnel)

                    r_proxy = requests.get(rport_details['url'].
                                           replace("443", tunnel['data']['lport']))

                    if ip_address in r_proxy.text:
                        self.logger.error("%s found in %s", ip_address, r_proxy.text)
                        self.summary['failures'].append("http_proxy response: " + r_proxy.text)
                    else:
                        self.logger.info("http_proxy: %s not in %s", ip_address, r_proxy.text)

                    # and now store service forwarding
                    # https://tracker.cloudradar.info/issue/DEV-2377

                    payload = {
                        "name": c['name'],
                        "remote_ip": "demo.ip-api.com",
                        "remote_port": 443,
                        "scheme": "https",
                    }

                    r_stored = requests.post(rport_details['url'] + "/api/v1/clients/"
                                             + c["id"] + "/stored-tunnels",
                                             json=payload,
                                             headers=auth_header)
                    stored = r_stored.json()
                    self.has_no_errors(stored)

                    r_get_stored = requests.get(rport_details['url'] + "/api/v1/clients/"
                                                + c["id"] + "/stored-tunnels",
                                                headers=auth_header)
                    get_stored = r_get_stored.json()
                    self.has_no_errors(get_stored)

                    if get_stored['data'][0]['remote_ip'] != stored['data']['remote_ip']:
                        self.summary['failures'].append("Stored tunnels failed: %s, %s" %
                                                        (stored['data']['remote_ip'],
                                                         get_stored['data'][0]['remote_ip']))
                    else:
                        self.logger.info("Stored tunnels ok: %s", stored['data'])

                    # -----------------------------------------------------------
                    # ++++ API commands and scripts
                    # -----------------------------------------------------------
                    # execute command on a single_host
                    # https://tracker.cloudradar.info/issue/DEV-2316

                    payload = {
                        "command": "ls -l /",
                        "timeout_sec": 10
                    }
                    r_command = requests.post(rport_details['url'] + "/api/v1/clients/"
                                              + c["id"] + "/commands",
                                              json=payload,
                                              headers=auth_header)
                    command = r_command.json()
                    if self.has_no_errors(command) == "ok":
                        r_command = requests.get(rport_details['url'] + "/api/v1/clients/"
                                                 + c["id"] + "/commands/" + command['data']['jid'],
                                                 headers=auth_header)
                        command = r_command.json()
                        if self.has_no_errors(command) != "ok" or \
                                command['data']['status'] != "successful":
                            self.summary['failures'].append(command)
                        self.summary['single-host'].append(command['data']['status'])
                    else:
                        self.summary['single-host'].append(command)

                    # execute a script (pwd Base64 encoded) on a single_host
                    # one script should fail as sudo is not allowed

                    payload = {
                        "script": "cHdkCg==",
                        "timeout_sec": 60,
                        "is_sudo": True
                    }
                    r_script = requests.post(rport_details['url'] + "/api/v1/clients/"
                                             + c["id"] + "/scripts",
                                             json=payload,
                                             headers=auth_header)
                    script = r_script.json()

                    if self.has_no_errors(script) == "ok":
                        r_script = requests.get(rport_details['url'] + "/api/v1/clients/"
                                                + c["id"] + "/commands/" + script['data']['jid'],
                                                headers=auth_header)
                        script = r_script.json()

                        if not parser_conf.get(c["hostname"], 'client_inst_args').count("-s"):
                            self.logger.info("No sudo rules must be created. No -s arg")
                            if script['data']['status'] == "failed":
                                self.summary['single-host-script'].append("ok")
                            else:
                                self.logger.error("Exec command should fail on this client")
                                self.summary['failures'].append(script)
                        else:
                            self.summary['single-host-script'].append(self.has_no_errors(script))
                    else:
                        self.summary['single-host-script'].append(script)

                    time.sleep(5)

                    # execute a script Base64 encoded on a single_host
                    # #!/usr/bin/env python3
                    # print("ok")
                    # is_sudo is false now

                    payload = {
                        "script": "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwpwcmludCgib2siKQ==",
                        "timeout_sec": 60,
                        "is_sudo": False
                    }
                    r_script = requests.post(rport_details['url'] + "/api/v1/clients/"
                                             + c["id"] + "/scripts",
                                             json=payload,
                                             headers=auth_header)
                    script = r_script.json()

                    if self.has_no_errors(script) == "ok":
                        r_script = requests.get(rport_details['url'] + "/api/v1/clients/"
                                                + c["id"] + "/commands/" + script['data']['jid'],
                                                headers=auth_header)
                        script = r_script.json()

                        if parser_conf.getboolean(c["hostname"], 'has_python') and\
                                script['data']['result']['stdout'].count("ok"):
                            self.summary['single-host-script-shebang'].append("ok")
                        else:
                            if self.has_no_errors(script) and \
                                    script['data']['result']['stderr'].count("‘python3’: No such")\
                                    and script['data']['status'] == 'failed':
                                self.summary['single-host-script-shebang'].append("ok")
                            else:
                                self.summary['single-host-script-shebang'].append(script)
                    else:
                        self.summary['single-host-script-shebang'].append(script)

                # -----------------------------------------------------------
                # execute a script on multiple hosts using websocket
                # rport --version encoded base64
                # read rport clients version
                # -----------------------------------------------------------
                payload = {
                    "script": "cnBvcnQgLS12ZXJzaW9u",
                    "client_ids": self.summary['client-ids'],
                    "group_ids": [],
                    "timeout_sec": 60,
                    "execute_concurrently": True,
                    "is_sudo": False,
                    "abort_on_error": True,
                    "interpreter": "",
                    "cwd": ""
                }

                websocket.enableTrace(True)
                ws = websocket.WebSocket()

                ws_url = "wss://%s.rport.io/api/v1/ws/scripts?access_token=%s" % \
                         (rport_details['record'], bearer_token)
                ws.connect(ws_url)

                self.logger.info('Sending ws: %s', payload)
                ws.send(json.dumps(payload))

                for _ in range(len(self.summary['client-ids'])):
                    result = ws.recv()
                    result = json.loads(result)
                    self.logger.info("Received ws: %s", result)
                    self.summary['multi-hosts'].append(result['result']['stdout'].strip("\n"))

                # tacoscript
                # https://tracker.cloudradar.info/issue/DEV-2408

                # yaml:
                # test1:
                #   cmd.run:
                #     - name: date +%s
                #
                # test2:
                #   file.managed:
                #     - name: /tmp/my-file.txt
                #     - contents: |
                #         My file content
                #         goes here
                #         Funny file
                #
                # test3:
                #   cmd.run:
                #     - names:
                #       - cat /tmp/my-file.txt
                #       - rm -f /tmp/my-file.txt

                script_encoded = 'dGVzdDE6CiAgY21kLnJ1bjoKICAgIC0gbmFtZTogZGF0ZSAr' \
                                 'JXMKICAgIAp0ZXN0MjoKICBmaWxlLm1hbmFnZWQ6CiAgICAt' \
                                 'IG5hbWU6IC90bXAvbXktZmlsZS50eHQKICAgIC0gY29udGVu' \
                                 'dHM6IHwKICAgICAgICBNeSBmaWxlIGNvbnRlbnQKICAgICAg' \
                                 'ICBnb2VzIGhlcmUKICAgICAgICBGdW5ueSBmaWxlCiAgICAg' \
                                 'ICAgCnRlc3QzOgogIGNtZC5ydW46CiAgICAtIG5hbWVzOiAK' \
                                 'ICAgICAgLSBjYXQgL3RtcC9teS1maWxlLnR4dAogICAgICAt' \
                                 'IHJtIC1mIC90bXAvbXktZmlsZS50eHQ= '
                payload = {
                    "script": script_encoded,
                    "client_ids": self.summary['client-ids'],
                    "group_ids": [],
                    "timeout_sec": 60,
                    "execute_concurrently": True,
                    "is_sudo": False,
                    "abort_on_error": True,
                    "interpreter": "tacoscript",
                    "cwd": ""
                }

                ws_url = "wss://%s.rport.io/api/v1/ws/scripts?access_token=%s" % \
                         (rport_details['record'], bearer_token)
                ws.connect(ws_url)

                self.logger.info('Sending ws: %s', payload)
                ws.send(json.dumps(payload))

                for _ in range(len(self.summary['client-ids'])):
                    result = ws.recv()
                    result = json.loads(result)
                    self.logger.info("Received ws: %s", result)
                    self.summary['tacoscript'].append(result['status'])

                    self.logger.info(result['result']['stdout'].strip("\n"))
                    if result['result']['stderr']:
                        self.logger.error(result['result']['stderr'].strip("\n"))

                    # 3 tests succeed
                    if not result['result']['stdout'].count("Succeeded: 3"):
                        self.summary['failures'].append(result['result']['stdout'])

                # -----------------------------------------------------------
                # ++++ API all tunnels endpoint
                # https://tracker.cloudradar.info/issue/DEV-2400
                # -----------------------------------------------------------

                active_tunnels = requests.get(rport_details['url'] + "/api/v1/tunnels",
                                              headers=auth_header).json()
                self.has_no_errors(active_tunnels)

                if not active_tunnels['data'] or len(active_tunnels['data']) != 9 or\
                        active_tunnels['data'][8]['host_header'] != 'demo.ip-api.com':
                    self.logger.error("active /tunnels failed: %s", active_tunnels['data'])
                    self.summary['failures'].append("/tunnels failed: %s" % active_tunnels['data'])
                else:
                    self.logger.info("active /tunnels ok")

            else:
                self.logger.error("No clients available")
                self.summary['failures'].append("No clients available")
                raise Exception("No clients available. Terminating.")

        except Exception as error:
            self.logger.error("Test failed with the following error: %s", error)
            self.summary['failures'].append(error)
            raise

        finally:

            # -----------------------------------------------------------
            # ++++ Tear down servers and clients
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
            self.logger.info("API create user: %s", self.summary['create-user'])
            self.logger.info("API log in created user: %s", self.summary['log-in-new-user'])
            self.logger.info("API clients-auth: %s", self.summary['clients-auth'])
            self.logger.info("Instance(s) successfully created: %d out of images: %d %s",
                             len(instances), len(images), images)
            self.logger.info("API tunnel(s) successfully created: (%d out of instances %d) %s",
                             len(self.summary['tunnels']), len(instances),
                             self.summary['tunnels'])
            self.logger.info("SSH connected to the endpoint of the tunnels: %s",
                             self.summary['ssh-connected-clients'])
            self.logger.info("API execute command on a single host: %s",
                             self.summary['single-host'])
            self.logger.info("API execute script on a single host: %s",
                             self.summary['single-host-script'])
            self.logger.info("API execute script w/ shebang: %s",
                             self.summary['single-host-script-shebang'])
            self.logger.info("API websocket multiple clients (clients version): %s",
                             self.summary['multi-hosts'])
            self.logger.info("API websocket execute taco script on multiple clients: %s",
                             self.summary['tacoscript'])
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
        Executes a command on a given instance
        """

        stderr = None
        for _ in range(3):
            (exit_code, stdout, stderr) = instance.execute(command)
            if exit_code != 0:
                self.logger.warning("stderr: %s", stderr)
                self.logger.warning("stdout: %s", stdout)
                self.logger.info("Something went wrong while exec: %s Don't you worry,"
                                 " we re-try up to 3 attempts", command)
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
        """

        if response.get("errors"):
            self.logger.error("Request exited with errors: %s", response)
            self.summary['failures'].append(response)
            return response
        self.logger.info("Request ok: %s", response)
        return "ok"

    def wait_for_instance_state(self, instance, state):

        """
        Awaits up to 5 mins for an instance to
        change to a specified state
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
