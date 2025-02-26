try:
    from locust import HttpUser, TaskSet, task
except ImportError:
    # For older versions of Locust
    from locust import HttpLocust as HttpUser, TaskSet, task


class UserTasks(TaskSet):
    @task
    def hello_world(self):
        self.client.get("/hello")
        self.client.get("/world")


class HelloWorldUser(HttpUser):
    host = "http://127.0.0.1:8089"
    task_set = UserTasks
