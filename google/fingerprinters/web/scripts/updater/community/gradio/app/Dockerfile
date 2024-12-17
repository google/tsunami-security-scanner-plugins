FROM python:3.9-slim

ARG version

COPY tooling-requirements.txt /

RUN python -m pip install --require-hashes -r /tooling-requirements.txt

RUN echo "gradio==$version" > /gradio-requirements.in

RUN pip-compile --generate-hashes /gradio-requirements.in \
      -o /requirements.txt

FROM python:3.9-slim

COPY --from=0 /requirements.txt /tmp/

RUN python -m pip install --require-hashes -r /tmp/requirements.txt

ADD test_app.py /workspace/

EXPOSE 8000

CMD [ "python3" , "/workspace/test_app.py" ]

