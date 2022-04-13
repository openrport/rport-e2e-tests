import os
import base64
import time
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools
from apiclient import errors

# full access
SCOPES = 'https://mail.google.com/'
BASEDIR = os.path.abspath(os.path.dirname(__file__))


class ApiGmail:

    """
    Gmail API
    """

    def __init__(self, logger):
        self.logger = logger
        self.name = self.__class__.__name__

    @staticmethod
    def get_service():

        """
        Gets service object
        """
        store = file.Storage(os.path.join(BASEDIR, 'token.json'))
        creds = store.get()
        if not creds or creds.invalid:
            flow = client.flow_from_clientsecrets(os.path.join(BASEDIR, 'credentials.json'), SCOPES)
            creds = tools.run_flow(flow, store)
        service = build('gmail', 'v1', http=creds.authorize(Http()))
        return service

    def get_emails_by_email(self, email):

        """
        Get emails filtered by email provided
        :param email: provided email
        :return:
        """

        service = self.get_service()
        emails = []

        self.logger.info("Get emails by email: %s", email)

        for _ in range(25):

            results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
            messages = results.get('messages', [])

            if not messages:
                self.logger.info("No messages found.")
                time.sleep(10)
            else:
                for message in messages:
                    msg = service.users().messages().get(userId='me', id=message['id']).execute()

                    result = {"email": email}

                    for header in msg.get('payload').get('headers'):

                        if header.get('name') == "To" and header.get('value') == email:
                            self.logger.info("Found matching email message: %s", msg['snippet'])
                            try:
                                data = msg['payload']['parts'][1]['body']['data']
                            except Exception:
                                self.logger.debug("attempt taking data from payload w/o parts")
                                data = msg['payload']['body']['data']

                            decoded_data = base64.urlsafe_b64decode(data.encode('UTF-8'))
                            result['content'] = str(decoded_data)

                    emails.append(result)

                if emails:
                    emails.reverse()
                    return emails
                self.logger.info("No messages found matching email address.")
                time.sleep(6)

    def wait_for_emails(self, expected_emails=1):

        """
        Waits for x gmail emails to arrive
        :param expected_emails: how many emails
        :return: emails from inbox
        """

        service = self.get_service()

        for _ in range(60):
            emails = []

            results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
            messages = results.get('messages', [])

            if not messages:
                self.logger.info("No messages found.")
            else:
                for message in messages:
                    msg = service.users().messages().get(userId='me', id=message['id']).execute()

                    has_from_subject = [False, False]  # from, subject
                    for header in msg.get('payload').get('headers'):
                        if header.get('name') == "From" and header.get('value').\
                                count("RPort two-factor authentication"):
                            self.logger.info("Found rport message: %s", msg['snippet'])
                            has_from_subject[0] = True
                        if header.get('name') == "Subject":
                            has_from_subject[1] = header.get('value')

                    if all(has_from_subject):
                        data = msg['payload']['parts'][0]['body']
                        decoded_data = base64.urlsafe_b64decode(data.encode('UTF-8'))
                        has_from_subject.append(decoded_data)

                    emails.append(has_from_subject)

            if len(emails) == expected_emails:
                self.logger.info("Emails: %s", emails)
                return emails
            self.logger.info("Found emails: %d != %d", len(emails), expected_emails)
            time.sleep(0.9)

    def delete_all_emails(self):

        """Delete all emails in gmail inbox"""

        try:
            service = self.get_service()

            results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
            messages = results.get('messages', [])

            for message in messages:
                service.users().messages().delete(userId='me', id=message['id']).execute()
                self.logger.info('Message with id: %s deleted successfully.' % message['id'])
        except errors.HttpError as err:
            self.logger.error('An error occurred: %s', err)
