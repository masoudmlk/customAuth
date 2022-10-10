import uuid
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.core.cache import cache
from rest_framework.mixins import ListModelMixin
from rest_framework.viewsets import GenericViewSet
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status

from core.serializers import UserRegisterSerializer, UserSerializer, TokenSerializer, UserLoginSerializer, \
    UserSendOtpSerializer, UserOtpValidateSerializer, UserChangePassSerializer, \
    UserForgetPassSerializer, TokenGeneralSerializer, KillTokensSerialiser
from core.models import User, Token
from core.utils import SMSService


class CustomAuthViewSet(ListModelMixin, GenericViewSet):

    ACTIONS = {'register': 'register', 'login': 'login', 'logout': 'logout',
               'send_otp': 'send_otp', 'validate_otp': 'validate_otp',
               "change_pass": "change_pass", "forget_pass": "forget_pass",
               "list_tokens": "list_tokens", "kill_tokens": "kill_tokens"}

    timeout_cache_token = 4 * 60

    @staticmethod
    def get_phone_cache_key(key: str) -> str:
        return f"phone-{key}"

    def get_queryset(self):
        return []

    def get_serializer_class(self):
        if self.action == self.ACTIONS['register']:
            return UserRegisterSerializer
        elif self.action == self.ACTIONS['login']:
            return UserLoginSerializer
        elif self.action == self.ACTIONS['send_otp']:
            return UserSendOtpSerializer
        elif self.action == self.ACTIONS['validate_otp']:
            return UserOtpValidateSerializer
        elif self.action == self.ACTIONS['change_pass']:
            return UserChangePassSerializer
        elif self.action == self.ACTIONS['forget_pass']:
            return UserForgetPassSerializer
        elif self.action == self.ACTIONS['list_tokens']:
            return TokenGeneralSerializer
        elif self.action == self.ACTIONS['kill_tokens']:
            return KillTokensSerialiser
        else:
            return UserSerializer

    def get_permissions(self):
        permission_login_required = [
            self.ACTIONS['logout'], self.ACTIONS['validate_otp'],
            self.ACTIONS['change_pass'], self.ACTIONS['list_tokens'], self.ACTIONS['kill_tokens']
        ]
        if self.action in permission_login_required:
            return [IsAuthenticated()]
        else:
            return [AllowAny()]

    def get_serializer_context(self):
        return {'user_id': self.request.user.id}

    @action(methods=['POST'], detail=False, url_name='register',)
    def register(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # create user
        user = User.objects.create_user(serializer.validated_data.get('username'),
                                        password=serializer.validated_data.get('password'),
                                        phone=serializer.validated_data.get('phone'))

        user.save()

        # create token
        userAgent = request.META.get('HTTP_USER_AGENT')
        token = Token.objects.create(user=user, user_agent=userAgent, )
        # serialize token
        serializerToken = TokenSerializer(token)
        return Response(serializerToken.data, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, url_name='login')
    def login(self, request):

        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # get data from serializer
        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')

        # get user info and check conditions

        user = User.objects.filter(username=username).first()
        if user is not None and isinstance(user, User) and user.check_password(password):
            # use login django to login user
            auth_login(request, user)
            # create token for each login
            userAgent = request.META.get('HTTP_USER_AGENT')
            token = Token.objects.create(user=user, user_agent=userAgent, )

            serializerToken = TokenSerializer(token)
            return Response(serializerToken.data, status=status.HTTP_200_OK)

        return Response({"Error": "user is not valid"}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET'], detail=False, url_name='logout')
    def logout(self, request):
        if request.user.is_authenticated:
            # remove token for this client and logout
            userAgent = request.META.get('HTTP_USER_AGENT')
            Token.objects.filter(user_id=request.user.pk, user_agent=userAgent).delete()
            auth_logout(request)
            return Response(status=status.HTTP_204_NO_CONTENT)
        Response("user not login", status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_name='send_otp')
    def send_otp(self, request):
        serializer = UserSendOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data.get('phone')

        user_exists = User.objects.filter(phone=phone).exists()
        if user_exists:

            otp_code = CustomAuthViewSet.generate_otp()
            print(f"otp_code {otp_code} ".center(100, "-"))

            sms_service = SMSService.get_object(phone)
            sms_service.send_message("hello gay")

            cacheKey = CustomAuthViewSet.get_phone_cache_key(phone)

            cache.set(cacheKey, otp_code, self.timeout_cache_token)
            cache.set(otp_code, phone, self.timeout_cache_token)

            return Response("The message is sent", status=status.HTTP_200_OK)

        return Response({"Error": "there are not a user with this phone"}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_name='validate_otp')
    def validate_otp(self, request):
        cacheKey = CustomAuthViewSet.get_phone_cache_key(request.user.phone)
        serializer = UserOtpValidateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        input_otp_code = serializer.validated_data.get('otp_code')
        if request.user.is_authenticated:
            data = str(cache.get(cacheKey))

            if data == input_otp_code:
                user = User.objects.filter(username=request.user.username).first()
                if user is not None and isinstance(user, User):
                    user.is_verify_phone = True
                    user.save()

                    cache.delete(data)
                    cache.delete(cacheKey)

                    return Response(status=status.HTTP_200_OK)

            return Response('Your code is invalid or it is expired', status=status.HTTP_400_BAD_REQUEST)

        return Response("Authentication error", status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_name='change_pass')
    def change_pass(self, request):
        current_user = request.user
        user_agent = request.META.get('HTTP_USER_AGENT')

        serializer = UserChangePassSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        old_password = serializer.validated_data.get('old_password')

        if current_user.is_authenticated and current_user.check_password(old_password):
            current_user.set_password(serializer.validated_data.get('password'))
            token = Token.objects.filter(user=current_user, user_agent=user_agent).order_by('-created').first()
            return Response(TokenSerializer(token).data, status=status.HTTP_200_OK)

        return Response({"Error": "password is not correct or user not login"}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['POST'], detail=False, url_name='forget_pass')
    def forget_pass(self, request):
        # check input data
        serializer = UserForgetPassSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # get data
        otp_code = serializer.validated_data.get('otp_code')
        phoneNumber = cache.get(otp_code)

        if phoneNumber:
            user = User.objects.filter(phone=phoneNumber, is_verify_phone=1).first()
            # check user data and login if data is valid
            if user is not None and isinstance(user, User):
                user.set_password(serializer.validated_data.get("password"))
                user.save()

                # login user with django login
                auth_login(request, user)

                user_agent = request.META.get('HTTP_USER_AGENT')
                token = Token.objects.create(user=user, user_agent=user_agent)

                return Response(TokenSerializer(token).data, status=status.HTTP_200_OK)

            return Response({"Error": "there is not any user with this phone number "
                                      "or the phone number is not active"},
                            status=status.HTTP_400_BAD_REQUEST)

        return Response({"Error": "this code is not valid."}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['GET'], detail=False, url_name='list_tokens')
    def list_tokens(self, request):
        queryset = Token.objects.filter(user=request.user).order_by('-created').all()
        serializer = TokenGeneralSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, url_name='kill_tokens')
    def kill_tokens(self, request):
        # set context for access in serialzer
        context = {'user_id': request.user.pk}
        # check is valid by serializer
        serializer = KillTokensSerialiser(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        # delete selected tokens
        Token.objects.filter(key__in=serializer.validated_data.get('token_keys')).delete()
        remindedTokens = Token.objects.filter(user_id=request.user.pk)

        return Response(TokenSerializer(remindedTokens).data, status=status.HTTP_200_OK)

    @action(methods=['GET'], detail=False, url_name='test')
    def test(self, request):
        userAgent = request.META.get('HTTP_USER_AGENT')
        tkents = Token.objects.filter(user_id=request.user.pk, user_agent=userAgent)
        tkents.delete()
        # a = CustomAuthViewSet.generate_otp()
        return Response(TokenGeneralSerializer(tkents, many=True).data, status=status.HTTP_200_OK)

    @staticmethod
    def generate_otp():
        return uuid.uuid4()
