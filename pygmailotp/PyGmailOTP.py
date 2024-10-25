import base64
import os
import pickle
import email
from email import policy
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build
from bs4 import BeautifulSoup as bs
import re
import importlib.resources
import yaml

class PyGmailOTP():
    def __init__(self, config_path=None, cred_path=None, debug=False):
        """
        Initialize PyGmailOTP class with scopes, query, OTP pattern, and an optional debug flag.
        :param config: List of OAuth scopes
        :param credentials: Gmail query string for searching emails
        :param otp_pattern: Regex pattern for extracting OTPs
        :param debug: Whether to print debug information (default: False)
        """
        self.debug = debug # Store the debug flag
        # Load Config
        self.config=self.load_config(config_path) if config_path else self.load_config()
        # Load Credentials
        self.credentials=self.load_credentials(cred_path) if cred_path else self.load_credentials()
        self.service = None 

    def load_config(self,config_path=None):
        '''
        @params
        config_path - custom path specified by the user to specify the config file, if not exists, loads from default locations
        '''
        user_config_path = os.path.expanduser("~/.PyGmailOTP/config.yaml")
        system_config_path = "/etc/PyGmailOTP/config.yaml"

        if config_path:
            with open(config_path) as file:
                return yaml.safe_load(file)

        if os.path.exists(user_config_path):
            with open(user_config_path) as file:
                return yaml.safe_load(file) 

        if os.path.exists(system_config_path):
            with open(system_config_path) as file:
                return yaml.safe_load(file) 

    def get_new_credentials(self, credentials_json):
        user_pickle_path = os.path.expanduser("~/.PyGmailOTP/token.pickle")
        user_credentials_file=os.path.expanduser("~/.PyGmailOTP/credentials.json")
        if os.path.exists(user_credentials_file):
            flow = InstalledAppFlow.from_client_secrets_file(user_credentials_file, self.config.get('scopes'))
            creds = flow.run_local_server(port=0)
            self.log("New credentials obtained.")
        # Save the updated credentials for future use
        with open(os.path.expanduser(user_pickle_path), 'wb') as token:
            pickle.dump(creds, token)
            self.log("Saved new credentials to pickle file.")
        return creds
        
        
    def load_credentials(self, cred_path=None):
        '''
        @params
        cred_path - a custom path specified by the user to find a pickle file, if not exists, loads from default locations
        '''
        creds = None
        user_credentials_file=os.path.expanduser("~/.PyGmailOTP/credentials.json")
        user_pickle_path = os.path.expanduser("~/.PyGmailOTP/token.pickle")
        if cred_path and os.path.exists(cred_path):
            with open(cred_path) as file:
                creds = pickle.load(file)
        if os.path.exists(user_pickle_path): 
            with open(user_pickle_path, 'rb') as file:
                creds = pickle.load(file)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    self.log("Credentials refreshed.")
                except RefreshError as e:
                    self.log(f"Refresh error occured: {e}")
                    creds = self.get_new_credentials(user_credentials_file)
            else:
                creds = self.get_new_credentials(user_credentials_file)
        return creds
            

    def log(self, message):
        """
        Prints the message if debug is enabled.
        :param message: The message to print if debug mode is enabled.
        """
        if self.debug:
            print(f"[DEBUG]: {message}")


    def initialize_service(self):
        """
        Initialize Gmail API service with the provided credentials.
        """
        self.service = build('gmail', 'v1', credentials=self.credentials)
        self.log("Gmail API service initialized.")

    def get_otp_emails(self):
        """
        Fetch unread OTP emails based on query and return message objects.
        """
        if not self.service:
            raise Exception("Service not initialized. Call `initialize_service` first.")
        
        try:
            self.log(f"Running Gmail query: {self.config.get('email_query')}")
            results = self.service.users().messages().list(userId='me', q=self.config.get('email_query'), maxResults=10).execute()
            messages = results.get('messages', [])
            self.log(f"Found {len(messages)} matching messages.")
            return messages
        except Exception as e:
            print(f"An error occurred while attempting to collect email messages: {e}")
            return None

    def extract_otps(self, messages):
        """
        Process Gmail messages, extract OTP from each, and mark emails as read.
        """
        if not self.service:
            raise Exception("Service not initialized. Call `initialize_service` first.")
        
        otps = []
        for message in messages:
            try:
                # Get raw email message
                raw_msg = self.service.users().messages().get(userId='me', id=message['id'], format='raw').execute()
                msg_str = base64.urlsafe_b64decode(raw_msg['raw'].encode('ASCII')).decode('utf-8')
                mime_msg = email.message_from_string(msg_str, policy=policy.default)
                self.log(f"Processing message from: {mime_msg['From']}, Subject: {mime_msg['Subject']}")

                # Extract body from email (plain text or HTML)
                body = self.extract_email_body(mime_msg)

                # Search for OTP using regex
                otp = re.search(self.config.get('otp_pattern'), body)
                if otp:
                    otps.append(otp.group(1))
                    self.log(f"Extracted OTP: {otp.group(1)}")

                # Mark the message as read
                self.service.users().messages().modify(
                    userId='me',
                    id=message['id'],
                    body={'removeLabelIds': ['UNREAD']}
                ).execute()
                self.log(f"Marked message {message['id']} as read.")

            except Exception as e:
                print(f"Error processing message {message['id']}: {e}")

        return otps if otps else None

    def extract_email_body(self, mime_msg):
        """
        Extract and return the email body, handling both plain text and HTML content.
        """
        body = ""
        for part in mime_msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode('utf-8')
            elif part.get_content_type() == "text/html":
                body = bs(part.get_payload(decode=True).decode('utf-8'), "html.parser").get_text()
        return body
