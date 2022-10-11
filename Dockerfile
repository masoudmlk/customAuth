FROM python:3.9-alpine

WORKDIR /customAuth


COPY requirements.txt /customAuth/requirements.txt
RUN pip install -r requirements.txt

# Now copy in our code, and run it
COPY . /customAuth
EXPOSE 8000
