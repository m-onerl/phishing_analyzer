from unittest.mock import Mock, patch
from src.email_analyzer import EmailAnalyzer
from src.imap_client import IMAPClient
from src.link_analyzer import LinkAnalyzer

def test_integration_flow():
    with patch("src.imap_client.IMAPClient") as MockIMAPClient:
        mock_imap_instance = MockIMAPClient.return_value
        mock_imap_instance.fetch_emails.return_value = [("1", "Email with http://example.com")]
        mock_imap_instance.parse_email_content.return_value = ("Email with http://example.com", False)
        mock_imap_instance.extract_links.return_value = ["http://example.com"]

        with patch("src.link_analyzer.LinkAnalyzer") as MockLinkAnalyzer:
            mock_link_analyzer = MockLinkAnalyzer.return_value
            mock_link_analyzer.check_link_virustotal.return_value = {"status": "safe"}

            result_queue = Mock()
            email_analyzer = EmailAnalyzer(mock_imap_instance, mock_link_analyzer, result_queue)

            email_analyzer.analyze_emails(
                server="imap.test.com",
                port=993,
                email="user@test.com",
                password="password"
            )

            mock_imap_instance.fetch_emails.assert_called_once()
            mock_imap_instance.parse_email_content.assert_called_once()
            mock_link_analyzer.check_link_virustotal.assert_called_once_with("http://example.com")
