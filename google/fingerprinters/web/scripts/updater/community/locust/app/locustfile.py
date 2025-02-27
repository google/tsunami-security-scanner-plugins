try:
    from locust import HttpUser, TaskSet, task
except ImportError:
    # For older versions of Locust
    from locust import HttpLocust as HttpUser, TaskSet, task


def index(l):
    l.client.get("/")


def stats(l):
    l.client.get("/stats/requests")


class UserTasks(TaskSet):
    # one can specify tasks like this
    tasks = [index, stats]

    # but it might be convenient to use the @task decorator
    @task
    def page404(self):
        self.client.get("/does_not_exist")
        self.client.get("/hello")
        self.client.get("/world")


class HelloWorldUser(HttpUser):
    host = "http://127.0.0.1:8089"
    tasks = [UserTasks]
    # version <= 1.14.5
    task_set = UserTasks
