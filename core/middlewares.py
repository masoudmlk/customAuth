from django.shortcuts import redirect
from django import http
from django.urls import reverse
from core.models import Token
from django.urls import resolve
from core.utils import Client
from core.views import UserAuthViewSet


class CheckTokenMiddleware:
    response_redirect_class = http.HttpResponsePermanentRedirect
    ROUTE_DEFAULT = 'user-auth-register'
    PATH_ALLOW_ANY = ['user-auth-register', 'user-auth-login', 'user-auth-forget_pass',
                      'otp-send_otp']

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        #
        user = request.user
        current_url = resolve(request.path_info).url_name

        # url with allow any access by all clients
        if current_url in CheckTokenMiddleware.PATH_ALLOW_ANY:
            response = self.get_response(request)
            return response

        # logged user can access base of token and user agent that stored in the database
        if request.user.is_authenticated:

            userAgent = Client.get_user_agent(request)
            token_exists = Token.objects.filter(user_id=user.pk, user_agent=userAgent).exists()

            if token_exists:
                response = self.get_response(request)
                return response
        """
        if url need to permission and there are not related token for user in the database, the route redirect to default route      
        """
        return self.response_redirect_class(reverse(CheckTokenMiddleware.ROUTE_DEFAULT))
