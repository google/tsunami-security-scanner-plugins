import argparse
import io
import re
import requests


class ApacheAirflowCVE202138540Detector(object):
    """
    This plugin will Detect CVE202138540 Vulnerable Airflow instances
    """
    CSRF_TOKEN_PATTERN = '<input id="csrf_token" name="csrf_token" type="hidden" value="(.*?)">'
    VUL_REDIRECT_STR = '<a href="/"'

    def __init__(self, baseuri):
        self.baseUri = baseuri
        self.csrf_token_url = self.baseUri + "login/"
        self.target_url = self.baseUri + "variable/varimport"

    def get_session_csrf(self):
        """
        Getting CSRF token and session cookie to hit POST req on target endpoint
        :return:
        """
        response = requests.get(self.csrf_token_url)
        session = response.cookies['session']
        csrf_token = re.findall(ApacheAirflowCVE202138540Detector.CSRF_TOKEN_PATTERN, str(response.text))[0]
        return session, csrf_token

    def passive_file_upload_on_varimport(self):
        """
        This function will hit the vulnerable endpoint to gather info.
        Empty Dictionary is used to make it passive.
        :return:
        """
        session, csrf_token = self.get_session_csrf()
        # For Active Scanning - content = '{"str_key": "str_value}'
        content = '{"hi":"hello"}'
        bytes_content = io.BytesIO(bytes(content, encoding='utf-8'))
        response = requests.post(self.target_url, data={"csrf_token": csrf_token}, files={'file': bytes_content},
                                 cookies={'session': session}, allow_redirects=False)
        return response.status_code, response.text

    @staticmethod
    def analyse_response(status_code, response_text):
        """
        This function will determine if the vulnerable airflow is running
        based on status code and the string in response text
        :param status_code:
        :param response_text:
        :return:
        """
        if status_code in [401, 403, 500]:
            return "NO", "Apache Airflow instance is not vulnerable"
        elif status_code == 302 and \
                ApacheAirflowCVE202138540Detector.VUL_REDIRECT_STR in response_text:
            return "YES", "Vulnerable: Redirection happened without authentication"
        else:
            return "NO", "Very old or Recent Apache Airflow is running, not vulnerable"

    def is_service_vulnerable(self):
        try:
            status_code, response_text = self.passive_file_upload_on_varimport()
            return ApacheAirflowCVE202138540Detector\
                .analyse_response(status_code,  response_text)
        except Exception as e:
            return "NO", str(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseUri", help="A constructed target web url http[s]")
    parser.add_argument("--output", help="An absolute path to output temp file")
    args = parser.parse_args()
    # flag can be YES NO
    flag, output_message = ApacheAirflowCVE202138540Detector(args.baseUri)\
        .is_service_vulnerable()
    print(flag, output_message)
    with open(args.output, "w+") as ofile:
        ofile.write(flag + " " + output_message)