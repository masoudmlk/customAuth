from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

from knox.auth import TokenAuthentication as BaseTokenAuthentication, AuthToken as BaseAuthToken
from core.utils import Client
from rest_framework import exceptions
from django.http import HttpResponseForbidden


class User(AbstractUser):
    phone = models.CharField(null=False, blank=False, unique=True, max_length=11)
    is_verify_phone = models.BooleanField(default=False)


class AuthToken(BaseAuthToken):
    user_agent = models.CharField(max_length=255, null=True)

    def __str__(self):
        return self.token_key


class TokenAuthentication(BaseTokenAuthentication):
    model = AuthToken

    def authenticate(self, request):
        if not Client.valid_user_agent(request):
            msg = _('Invalid user agent.')
            raise exceptions.PermissionDenied(msg)
        return super(TokenAuthentication, self).authenticate(request)
