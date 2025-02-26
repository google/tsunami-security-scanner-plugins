import requests


def get_locust_tags():
    url = "https://hub.docker.com/v2/repositories/locustio/locust/tags"
    tags = []
    while url:
        response = requests.get(url)
        data = response.json()
        tags.extend([tag['name'] for tag in data['results']])
        url = data['next']
    return tags


if __name__ == "__main__":
    tags = get_locust_tags()
    for tag in tags:
        print(tag)
