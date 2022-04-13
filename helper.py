import random
import string
import re
import subprocess
import os

SCRIPTS_PATH = os.path.join(os.getcwd(), "scripts")


class Helper(object):

    """
    Helps you run commands,
    Provides regular expression capabilities for pattern matching
    """

    def __init__(self, logger):
        self.logger = logger

    def get_random_string(self, chars):

        """
        Get a random string
        :param chars: how long the string needs to be
        :return:
        """
        return ''.join(random.choice(string.ascii_letters) for x in range(chars))

    def get_match_from_output(self, out, get_record=True):

        """
        Match strings in rport output
        :param out: rport output
        :param get_record:
        :return: rport credentials
        """
        m = re.search(r"Password = (\w+)", out)
        password = m.group(1)

        m = re.search(r"User .+= (\w+)", out)
        user = m.group(1)

        m = re.search(r"Point your browser to (.+) \n", out)
        url = m.group(1)

        record = None
        if get_record:
            m = re.search(r"https://(.+).rport.io", url)
            record = m.group(1)

        self.logger.info("password: %s, user: %s, url: %s, record: %s", password, user, url, record)

        return {"password": password, "user": user, "url": url, "record": record}

    def get_2fa_code_match(self, email):

        """
        Matches 2fa code from the email
        :param email: email with the code
        :return: 2fa code
        """
        m = re.search(r"<code>(\w+)</code>", email)
        code = m.group(1)
        self.logger.info("2fa code: %s", code)
        return code

    def run_command(self, command_list, args=None, script=True):

        """
        Runs command
        """
        if args is not None and script:
            cmd = [os.path.join(SCRIPTS_PATH, command_list), args]
        elif script:
            cmd = [os.path.join(SCRIPTS_PATH, command_list)]
        else:
            cmd = command_list
        self.logger.info("Run command: %s", cmd)
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
