import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import main

def test_application_full_flow(mocker):

    mocker.patch("src.imap_client.IMAPClient.login", return_value=True)
    mocker.patch("src.imap_client.IMAPClient.fetch_emails", return_value=["Email with http://example.com"])
    mocker.patch("src.link_analyzer.LinkAnalyzer.check_link_virustotal", return_value={"status": "safe"})

    result = main()
    assert result is not None
