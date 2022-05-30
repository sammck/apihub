FROM python:3.8

# 
WORKDIR /code

# 
COPY ./requirements.txt /code/requirements.txt

# 
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# 
COPY ./keycloak-init.py /code/keycloak-init.py

# 
ENTRYPOINT ["python3", "keycloak-init.py"]
