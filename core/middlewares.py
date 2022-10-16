from django.shortcuts import redirect
from django import http
from django.urls import reverse
from core.models import AuthToken, TokenAuthentication
from django.urls import resolve
from core.utils import Client
from core.views import UserAuthViewSet
from knox.settings import CONSTANTS as KNOX_CONSTANTS
from rest_framework.exceptions import APIException
from rest_framework.authentication import get_authorization_header
from rest_framework.response import Response
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions


class CheckTokenMiddleware:
    response_redirect_class = http.HttpResponsePermanentRedirect
    ROUTE_DEFAULT = 'user-auth-register'
    PATH_ALLOW_ANY = ['user-auth-register', 'user-auth-login', 'user-auth-forget_pass',
                      'otp-send_otp']

    def __init__(self, get_response):
        self.get_response = get_response

    @classmethod
    def _check_is_required_update_user_agent(cls, request):
        try:
            lstToken = get_authorization_header(request).split()
            if len(lstToken) == 2:
                auth_token = lstToken[1]
                auth_token = auth_token.decode("utf-8")
                sub_token_key = auth_token[:KNOX_CONSTANTS.TOKEN_KEY_LENGTH]
                authTokenObj = AuthToken.objects.only('token_key', 'user_agent').filter(
                    token_key=sub_token_key).first()
                print(authTokenObj, sub_token_key)
                user_agent, token_key = None, None
                if authTokenObj is not None and isinstance(authTokenObj, AuthToken):
                    user_agent, token_key = authTokenObj.user_agent, authTokenObj.token_key

                if user_agent != Client.get_user_agent(request) and authTokenObj is not None and isinstance(
                        authTokenObj, AuthToken):
                    authTokenObj.user_agent = Client.get_user_agent(request)
                    authTokenObj.save(update_fields=['user_agent'])
        except Exception:
            print(f"Error in {__file__}  {cls.__name__}")

    def __call__(self, request):
        self._check_is_required_update_user_agent(request)
        response = self.get_response(request)
        return response
