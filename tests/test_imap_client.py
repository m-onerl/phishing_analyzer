from unittest.mock import Mock, patch
from src.imap_client import IMAPClient


def test_imap_client_login_success():
    with patch("imaplib.IMAP4_SSL") as mock_imap_ssl:
        mock_mail = Mock()
        mock_imap_ssl.return_value = mock_mail
        mock_mail.login.return_value = "OK"

        client = IMAPClient(server="imap.test.com", port=993, email="test@test.com", password="test")
        result = client.login()

        assert result is True
        mock_mail.login.assert_called_once_with("test01@test.com", "test")


def test_fetch_emails_success():
    mock_mail = Mock()
    mock_mail.select.return_value = ("OK", [b"1"])
    mock_mail.search.return_value = ("OK", [b"1 2 3"])
    mock_mail.fetch.return_value = ("OK", [(b"1", b"Test email content")])

    client = IMAPClient()
    client.mail = mock_mail
    emails = client.fetch_emails()

    assert len(emails) == 3
    mock_mail.fetch.assert_called()
