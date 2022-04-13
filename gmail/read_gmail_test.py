from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools


# SCOPES:
# https://developers.google.com/gmail/api/auth/scopes

# HOW TO READ
# https://codehandbook.org/how-to-read-email-from-gmail-api-using-python/

# read only scope
# SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'

# API
# https://developers.google.com/gmail/api/v1/reference/users/messages/get

# CONSOLE
# https://console.developers.google.com/apis/dashboard?authuser=5&project=fybtest

# full access
SCOPES = 'https://mail.google.com/'


def main():

    """
    Developers only:
    To test API gmail setup
    """
    store = file.Storage('token.json')
    creds = store.get()
    if not creds or creds.invalid:
        flow = client.flow_from_clientsecrets('credentials.json', SCOPES)
        creds = tools.run_flow(flow, store)
    service = build('gmail', 'v1', http=creds.authorize(Http()))

    # Call the Gmail API to fetch INBOX
    results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No messages found.")
    else:
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()

            for header in msg[u'payload'][u'headers']:
                if header.get('name') == "From" and header.get('value').count("cloudradar"):
                    print("Found cloudradar message: ")
                    print(msg['snippet'])
                elif header.get('name') == "From":
                    print("Found non cloudradar message: ")
                    print(msg['snippet'])


if __name__ == "__main__":
    main()
