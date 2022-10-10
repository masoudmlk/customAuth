from django.db import models
from django.contrib.auth.models import AbstractUser
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken import models as token_models
from customAuth import settings
from rest_framework.authentication import TokenAuthentication


class User(AbstractUser):
    phone = models.CharField(null=False, blank=False, unique=True, max_length=11)
    is_verify_phone = models.BooleanField(default=False)


class Token(token_models.Token):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='auth_token',
        on_delete=models.CASCADE
    )
    user_agent = models.CharField(max_length=255, null=True)


