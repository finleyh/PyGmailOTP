# PyGmailOTP
This is a library you can configure to extract OTPs from specific email sources landing in your inbox.

## Requirements
This library currently leverages GMAIL, ill probably expand this out in the future and refactor the library, but GMAIL worked for my initial use case

You'll need to create a Google project that has READ and MODIFY permissions to a GMAIL account.

### Config files

During the creation of your Google Project, they should have prompted you to download a credentials.json file containing our OAUTH information.

That file will replace template_creds.json 
That file MUST be named 'credentials.json', and placed in one of the following locations to be seen by PyGmailOTP
* /etc/PyGmailOTP/
* ~/.PyGmailOTP/

template_config.yaml must be filled out with the following:
* SCOPE URLs (found in your Google Project) 
* an email query string that filters your emails down to the one you want to extract OTP out of (see Gmail documentation)
* a regex string specific to extracting your OTP message body. 



Your token.pickle containing credentials after OAUTH will be written to either of these directories also, after first execution.

### Installation of requirements
pip install -r requirements.txt


### Usage

The class was made with running in Docker in mind. This is a helper library to larger automation needs i have. So i know this shouldn't run as root, and relies on config files being dropped in places that can be read and accessed by root, but that is why.

Example Code: 

```
from pygmailotp.PyGmailOTP import PyGmailOTP

def main():

    # Initialize the PyGmail class with the loaded config
    gmail = PyGmailOTP(
        debug=True  # Or this can also come from YAML if needed
    )

    gmail.initialize_service()  # Initialize Gmail API service

    messages = gmail.get_otp_emails()  # Get OTP emails
    if messages:
        otps = gmail.extract_otps(messages)  # Extract OTPs
        print(f"Found OTPs: {otps}")

if __name__ == "__main__":
    main()
```
