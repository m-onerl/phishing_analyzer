from unittest.mock import Mock, patch
from src.link_analyzer import LinkAnalyzer


def test_check_link_virustotal():
    with patch("requests.get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_results": {
                        "Engine1": {"category": "clean", "result": "clean"},
                        "Engine2": {"category": "suspicious", "result": "phishing"},
                    }
                }
            }
        }
        mock_get.return_value = mock_response


        analyzer = LinkAnalyzer(virustotal_api_key="test_api_key")

        result = analyzer.check_link_virustotal("http://example.com")

        assert result["status"] == "suspicious"
        assert len(result["details"]) == 1 
        assert result["details"][0]["engine"] == "Engine2"

        mock_get.assert_called_once_with(
            "https://www.virustotal.com/api/v3/urls/aHR0cDovL2V4YW1wbGUuY29t",
            headers={"x-apikey": "test_api_key"},
            timeout=10
        )


def test_analyze_page_content():

    with patch("requests.head") as mock_head, patch("requests.get") as mock_get:

        mock_head_response = Mock()
        mock_head_response.headers = {"Content-Type": "text/html"}
        mock_head.return_value = mock_head_response

        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.text = """
            <html>
                <body>
                    <form>
                        <input name="password">
                        <input name="email">
                    </form>
                    <p>Login credentials are required.</p>
                </body>
            </html>
        """
        mock_get.return_value = mock_get_response

        analyzer = LinkAnalyzer(virustotal_api_key="test_api_key")
        result = analyzer.analyze_page_content("http://example.com")

        assert len(result) > 0
        assert "Form field: password" in result
        assert "Form field: email" in result
        assert "Keyword in text: login" in result

        mock_head.assert_called_once_with("http://example.com", timeout=10)
        mock_get.assert_called_once_with("http://example.com", timeout=10)
