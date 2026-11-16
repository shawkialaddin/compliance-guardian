# INTENTIONALLY VULNERABLE TEST FIXTURE (FastAPI/Django style) - do not deploy.
import jwt
import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
SECRET_KEY = "dj4ng0-1nsecure-K3y-9f8a7b6c5d"


def load_config(stream):
    return yaml.load(stream)


def read_token(token):
    return jwt.decode(token, options={"verify_signature": False})


def check_webhook(signature, expected_signature):
    return signature == expected_signature
