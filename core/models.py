from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken import models as token_models
from customAuth import settings
from knox.auth import TokenAuthentication as BaseTokenAuthentication, AuthToken as BaseAuthToken
from knox.models import AuthTokenManager as BaseAuthTokenManager
from knox import crypto
from knox.settings import CONSTANTS, knox_settings
from django.utils import timezone
from core.utils import Client

# from knox.auth import TokenAuthentication, AuthToken
from uuid import uuid4

class User(AbstractUser):
    phone = models.CharField(null=False, blank=False, unique=True, max_length=11)
    is_verify_phone = models.BooleanField(default=False)


class AuthToken(BaseAuthToken):
    user_agent = models.CharField(max_length=255, null=True)


class TokenAuthentication(BaseTokenAuthentication):
    model = AuthToken


