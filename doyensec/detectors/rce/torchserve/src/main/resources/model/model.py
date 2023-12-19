import hashlib
import urllib.request
import platform
import json

def produce_conformant_output(string, length):
    """Produce a list of length `length` with `string` as the first element."""
    return [string] + ["Ok"] * (length - 1)

def handle(data, context):
    """Handle a request to the model. Echoes the input string, unless special headers are set."""
    if (context is None) or (data is None):
        return None

    headers = context.get_all_request_header(0)
    if headers is None:
        return data

    response = data[0]
    if "tsunami-execute" in headers:
        # Calculate the MD5 hash of the headers["execute"] value
        response = hashlib.md5(headers["tsunami-execute"].encode()).hexdigest()
    elif "tsunami-callback" in headers:
        # Create a GET request to the headers["callback"] URL through standard library
        try:
            urllib.request.urlopen(headers["tsunami-callback"])
        except:
            pass
    elif "tsunami-info" in headers:
        # Collect some basic system info to simplify vulnerability mitigation
        info = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "hostname": platform.node()
        }
        response = json.dumps(info)

    elif "tsunami-log" in headers:
        # Log the headers["log"] value to the container's stdout
        print(headers["tsunami-log"])

    return produce_conformant_output(response, len(data))
