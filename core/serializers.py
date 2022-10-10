from django.core.validators import RegexValidator
from rest_framework import serializers
from core.models import User, Token
from rest_framework.fields import empty

from django.core import exceptions
import django.contrib.auth.password_validation as validators


def validate_password_and_repeat_password(data):
    if data.get('password') != data.get('password_repeat'):
        raise serializers.ValidationError({"dismatch password": "password and password repeat are not match"})

    # get the password from the data
    password = data.get('password')
    errors = dict()
    try:
        # validate the password and catch the exception
        validators.validate_password(password=password)
    # the exception raised here is different than serializers.ValidationError
    except exceptions.ValidationError as e:
        errors['password'] = list(e.messages)
    if errors:
        raise serializers.ValidationError(errors)
    return data


class UserSerializer(serializers.Serializer):
    class Meta:
        fields = ['id', 'username', 'email', 'first_name', 'last_name']


class UserRegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, required=True)
    password = serializers.CharField(max_length=255, write_only=True, required=True, )
    password_repeat = serializers.CharField(max_length=255, write_only=True, required=True, )
    phone = serializers.CharField(max_length=12, required=True, validators=[
        RegexValidator(
            regex='^0[0-9]{2,}[0-9]{7,}$',
            message='phone must be numeric with 11 digits',
            code='invalid_phone'
        ),
    ])

    class Meta:
        model = User
        fields = ['username', 'password', 'password_repeat', 'phone']

    def validate_phone(self, phone):
        existing = User.objects.filter(phone=phone).first()
        if existing:
            raise serializers.ValidationError(
                {'invalid phone': "Someone with that phone has already registered. Was it you?"})
        return phone

    def validate_username(self, username):
        username = str(username)
        if len(username) < 4:
            raise serializers.ValidationError(
                {'invalid username': "username is to small"})

        if username.isnumeric():
            raise serializers.ValidationError(
                {'invalid username': "username can not be a number"})

        existing = User.objects.filter(username=username).first()
        if existing:
            raise serializers.ValidationError(
                {'invalid username': "Someone with that username has already registered. Was it you?"})
        return username

    def validate(self, data):
        return validate_password_and_repeat_password(data)

    def save(self, **kwargs):
        key = "password_repeat"
        if self.validated_data.get(key):
            del self.validated_data[key]

        return super().save(**kwargs)


class TokenGeneralSerializer(serializers.ModelSerializer):
    key = serializers.CharField(read_only=True)

    class Meta:
        model = Token
        fields = ['key', 'user_agent', 'created']


class TokenSerializer(serializers.ModelSerializer):
    key = serializers.CharField(read_only=True)

    class Meta:
        model = Token
        fields = ['key']


class UserLoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['username', 'password']


class UserSendOtpSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=255, write_only=True)


class UserOtpValidateSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=255, write_only=True)


class UserChangePassSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(max_length=255, required=True, )
    password = serializers.CharField(max_length=255, write_only=True, required=True)
    password_repeat = serializers.CharField(max_length=255, write_only=True, required=True)

    class Meta:
        model = User
        fields = ['old_password', 'password', 'password_repeat']

    def validate(self, data):
        return validate_password_and_repeat_password(data)


class UserForgetPassSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=255, required=True)
    password = serializers.CharField(max_length=255, write_only=True, required=True)
    password_repeat = serializers.CharField(max_length=255, write_only=True, required=True)

    class Meta:
        model = User
        fields = ['otp_code', 'password', 'password_repeat']

    def validate(self, data):
        return validate_password_and_repeat_password(data)


class KillTokensSerialiser(serializers.Serializer):

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance, data, **kwargs)
        print(self.tokens())
        print(kwargs.get('request'))
        self.fields['token_keys'] = serializers.MultipleChoiceField(choices=self.tokens())

    def tokens(self):
        user_id = self.context.get('user_id')
        request = self.context.get('request')
        print({request})
        return [(row.key, str(row.created) + "-" + row.user_agent) for row in
                Token.objects.filter(user_id=user_id).all()]
