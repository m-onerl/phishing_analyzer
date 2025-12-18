import pytest
from unittest.mock import Mock
from src.email_analyzer import EmailAnalyzer

def test_email_analyzer_extract_links():
    mock_imap_client = Mock()
    mock_link_analyzer = Mock()
    result_queue = Mock()
    
    email_analyzer = EmailAnalyzer(mock_imap_client, mock_link_analyzer, result_queue)
    
    email_content = '''
    Click this link: http://example.com
    Also check https://anotherexample.com.
    '''
    mock_imap_client.extract_links.return_value = ["http://example.com", "https://anotherexample.com"]

    links = mock_imap_client.extract_links(email_content, is_html=False)
    assert len(links) == 2
    assert "http://example.com" in links
    assert "https://anotherexample.com" in links
