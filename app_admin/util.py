# Modules for Emails
from django.core.mail import EmailMessage, message

import threading
""" * Delcartion of Email Setting for Verification * """

# Email Congfigrations


class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class SendEmail:
    @staticmethod
    def send_email(data):

        # Email Format
        email = EmailMessage(
            subject=data["email_subject"],
            body=data["email_body"],
            to=[data["to_email"]],
        )

        email.content_subtype = "html"
        EmailThread(email).start()
