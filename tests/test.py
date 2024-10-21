import yaml  # Fixed import (pyyaml is yaml in Python)
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
