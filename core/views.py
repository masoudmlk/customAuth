import uuid
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.core.cache import cache
from rest_framework.viewsets import GenericViewSet
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework.serializers import Serializer
from core.serializers import UserRegisterSerializer, UserSerializer, TokenSerializer, UserLoginSerializer, \
    SendOtpSerializer, OtpValidateSerializer, UserChangePassSerializer, \
    UserForgetPassSerializer, TokenGeneralSerializer, KillTokensSerialiser
from core.models import User, Token
from core.utils import SMSService, Client


class UserAuthViewSet(GenericViewSet):
    ACTIONS = {'register': 'register', 'login': 'login', 'logout': 'logout',
               'validate_otp': 'validate_otp',
               "change_pass": "change_pass", "forget_pass": "forget_pass"}

    def get_queryset(self):
        return []

    def get_serializer_class(self):
        if self.action == self.ACTIONS['register']:
            return UserRegisterSerializer
        elif self.action == self.ACTIONS['login']:
            return UserLoginSerializer
        elif self.action == self.ACTIONS['validate_otp']:
            return OtpValidateSerializer
        elif self.action == self.ACTIONS['change_pass']:
            return UserChangePassSerializer
        elif self.action == self.ACTIONS['forget_pass']:
            return UserForgetPassSerializer
        else:
            return UserSerializer

    @staticmethod
    def get_permission_login_required():
        return [
            UserAuthViewSet.ACTIONS['logout'], UserAuthViewSet.ACTIONS['validate_otp'],
            UserAuthViewSet.ACTIONS['change_pass'],
        ]

    def get_permissions(self):
        permission_login_required = UserAuthViewSet.get_permission_login_required()
        if self.action in permission_login_required:
            return [IsAuthenticated()]
        else:
            return [AllowAny()]

    def get_serializer_context(self):
        return {'user_id': self.request.user.id}

    @action(methods=['POST', 'GET'], detail=False, url_name='register')
    def register(self, request):
        # if users logged in,  they can not access to this request or page such as login or register
        response = self.not_permission_logged_in_user(request)
        if response is not None:
            return response

        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # create user
        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')
        phone = serializer.validated_data.get('phone')
        user = User.objects.create_user(username, password=password, phone=phone)
        user.save()

        # create token
        token = UserAuthViewSet._createToken(user, request)
        return Response(TokenSerializer(token).data, status=status.HTTP_200_OK)

    @action(methods=['POST', 'GET'], detail=False, url_name='login')
    def login(self, request):
        # if users logged in,  they can not access to this request or page
        response = self.not_permission_logged_in_user(request)
        if response is not None:
            return response

        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # get data from serializer
        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')

        # get user info and check conditions
        user, isLogin = UserAuthViewSet.login_user(request, username=username, password=password)
        if isLogin and isinstance(user, User):
            token = UserAuthViewSet._createToken(user, request)
            return Response(TokenSerializer(token).data, status=status.HTTP_200_OK)
        return Response({"Error": "there are not any user with this username and password"},
                        status=status.HTTP_401_UNAUTHORIZED)

    @action(methods=['GET'], detail=False, url_name='logout')
    def logout(self, request):
        if request.user.is_authenticated:
            # remove token for this client and logout
            userAgent = Client.get_user_agent(request)
            Token.objects.filter(user_id=request.user.pk, user_agent=userAgent).delete()
            auth_logout(request)
            return Response(status=status.HTTP_204_NO_CONTENT)
        Response({"Error": "You are not login"}, status=status.HTTP_401_UNAUTHORIZED)

    @action(methods=['POST'], detail=False, url_name='validate_otp')
    def validate_otp(self, request):
        cacheKey = OTPViewSet.get_phone_cache_key(request.user.phone)
        serializer = OtpValidateSerializer(data=request.data)
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

            return Response('Your code is invalid or it is expired', status=status.HTTP_405_METHOD_NOT_ALLOWED)

        return Response("Authentication error", status=status.HTTP_401_UNAUTHORIZED)

    @action(methods=['POST'], detail=False, url_name='change_pass')
    def change_pass(self, request):
        current_user = request.user
        user_agent = Client.get_user_agent(request)

        serializer = UserChangePassSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        old_password = serializer.validated_data.get('old_password')

        if current_user.is_authenticated and current_user.check_password(old_password):
            current_user.set_password(serializer.validated_data.get('password'))
            current_user.save()
            token = Token.objects.filter(user=current_user, user_agent=user_agent).order_by('-created').first()
            return Response(TokenSerializer(token).data, status=status.HTTP_200_OK)

        return Response({"Error": "password is not correct or user not login"}, status=status.HTTP_401_UNAUTHORIZED)

    @action(methods=['POST'], detail=False, url_name='forget_pass')
    def forget_pass(self, request):
        # check input data
        serializer = UserForgetPassSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # get data
        otp_code = serializer.validated_data.get('otp_code')
        phoneNumber = cache.get(otp_code)
        password = serializer.validated_data.get("password")

        if phoneNumber:
            user, isLogin = UserAuthViewSet.login_user(request, phone=phoneNumber, is_verify_phone=1)
            if isLogin and user is not None and isinstance(user, User):
                # change password
                user.set_password(password)
                user.save()
                # create token
                token = UserAuthViewSet._createToken(user, request)

                return Response(TokenSerializer(token).data, status=status.HTTP_200_OK)

            return Response({"Error": "there is not any user with this phone number "
                                      "or the phone number is not active"},
                            status=status.HTTP_401_UNAUTHORIZED)
        return Response({"Error": "this code is not valid."}, status=status.HTTP_408_REQUEST_TIMEOUT)

    @staticmethod
    def login_user(request, user=None, username=None, password=None, phone=None, is_verify_phone=None) -> tuple:
        # login by user
        if user is not None and isinstance(user, User):
            auth_login(request, user)
            return user, True

        # login by phone
        if phone is not None:
            if is_verify_phone is not None:
                user = User.objects.filter(phone=phone, is_verify_phone=is_verify_phone).first()
            else:
                user = User.objects.filter(phone=phone).first()

            if user is not None and isinstance(user, User):
                auth_login(request, user)
                return user, True
            return user, False

        # login by username and password
        isLogin = False
        if username is not None and password is not None:
            user = User.objects.filter(username=username).first()
            if user is not None and isinstance(user, User) and user.check_password(password):
                isLogin = True
                auth_login(request, user)

        return user, isLogin

    @staticmethod
    def _createToken(user: User, request) -> Token:
        if not isinstance(user, User):
            raise {"Error": "user instance is not valid"}
        user_agent = Client.get_user_agent(request)
        token = Token.objects.create(user=user, user_agent=user_agent)
        return token

    def not_permission_logged_in_user(self, request, message_get=None, message_post=None):
        if message_post is None:
            message_post = "You have already logged in"
        if message_get is None:
            message_get = "You can not access to this page"

        if request.method == "GET":
            if request.user.is_authenticated:
                self.http_method_names = []
            return Response({"detail": message_get}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

        if request.method == "POST" and request.user.is_authenticated:
            self.http_method_names = []
            return Response({"detail": message_post}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class OTPViewSet(GenericViewSet):
    ACTIONS = {'send_otp': 'send_otp'}
    TIMEOUT_CACHE_TOKEN = 4 * 60

    @staticmethod
    def get_phone_cache_key(key: str) -> str:
        return f"phone-{key}"

    def get_queryset(self):
        return []

    def get_serializer_class(self):
        if self.action == self.ACTIONS['send_otp']:
            return SendOtpSerializer
        else:
            return UserSerializer

    @staticmethod
    def get_permission_login_required():
        return []

    def get_permissions(self):
        permission_login_required = UserAuthViewSet.get_permission_login_required()
        if self.action in permission_login_required:
            return [IsAuthenticated()]
        else:
            return [AllowAny()]

    def get_serializer_context(self):
        return {'user_id': self.request.user.id}

    @action(methods=['POST'], detail=False, url_name='send_otp')
    def send_otp(self, request):
        serializer = SendOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data.get('phone')

        user_exists = User.objects.filter(phone=phone).exists()
        if user_exists:
            otp_code = OTPViewSet.generate_otp()

            sms_service = SMSService.get_object(phone)
            sms_service.send_message(f"otp_code {otp_code} ".center(100, "-"))

            cacheKey = OTPViewSet.get_phone_cache_key(phone)

            cache.set(cacheKey, otp_code, self.TIMEOUT_CACHE_TOKEN)
            cache.set(otp_code, phone, self.TIMEOUT_CACHE_TOKEN)

            return Response("The message is sent", status=status.HTTP_200_OK)

        return Response({"Error": "there are not a user with this phone"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    @staticmethod
    def generate_otp():
        return uuid.uuid4()


class TokensViewSet(GenericViewSet):
    ACTIONS = {'list_tokens': 'list_tokens', 'kill_tokens': 'kill_tokens'}

    def get_queryset(self):
        return []

    def get_serializer_class(self):
        if self.action == self.ACTIONS['kill_tokens']:
            return KillTokensSerialiser
        else:
            return TokenGeneralSerializer

    @staticmethod
    def get_permission_login_required():
        return [TokensViewSet.ACTIONS['list_tokens'], TokensViewSet.ACTIONS['kill_tokens']]

    def get_permissions(self):
        permission_login_required = UserAuthViewSet.get_permission_login_required()
        if self.action in permission_login_required:
            return [IsAuthenticated()]
        else:
            return [AllowAny()]

    def get_serializer_context(self):
        return {'user_id': self.request.user.id}

    @action(methods=['GET'], detail=False, url_name='list_tokens')
    def list_tokens(self, request):
        queryset = Token.objects.filter(user=request.user).order_by('-created').all()
        serializer = TokenGeneralSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['POST'], detail=False, url_name='kill_tokens')
    def kill_tokens(self, request):

        context = {'user_id': request.user.pk}

        # check is valid by serializer
        serializer = KillTokensSerialiser(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        # delete selected tokens
        Token.objects.filter(key__in=serializer.validated_data.get('token_keys')).delete()
        remindedTokens = Token.objects.filter(user_id=request.user.pk)

        return Response(TokenSerializer(remindedTokens).data, status=status.HTTP_200_OK)
