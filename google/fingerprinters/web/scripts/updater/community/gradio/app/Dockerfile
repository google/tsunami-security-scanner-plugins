FROM python:3.9-slim

ARG version

RUN python -m pip install gradio==$version

ADD test_app.py /workspace/

EXPOSE 8000

CMD [ "python3" , "/workspace/test_app.py" ]