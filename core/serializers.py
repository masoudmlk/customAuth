from django.core.validators import RegexValidator, EmailValidator, MinValueValidator, MaxLengthValidator, \
    MinLengthValidator
from rest_framework import serializers
from core.models import User
from rest_framework.fields import empty

from django.core import exceptions
import django.contrib.auth.password_validation as validators
from core.validations import CoreValidation

from core.models import AuthToken


def validate_password_and_repeat_password(data):
    if data.get('password') != data.get('password_repeat'):
        raise serializers.ValidationError({"dismatch password": "password and password repeat are not match"})

    if data.get('old_password') is not None and data.get('old_password') == data.get('password'):
        raise serializers.ValidationError({"Error": "password password should not same as old password"})

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
        model = User
        fields = ['id', 'username', 'email']


class UserRegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=30, required=True,
                                     validators=[MinLengthValidator(8), MaxLengthValidator(30),
                                                 CoreValidation.username_regx_validator()])

    password = serializers.CharField(max_length=255, write_only=True, required=True, validators=[MinLengthValidator(8)])
    password_repeat = serializers.CharField(max_length=255, write_only=True, required=True,
                                            validators=[MinLengthValidator(8)])

    phone = serializers.CharField(max_length=11, required=True, validators=[
        CoreValidation.phone_regx_validator(),
        MinLengthValidator(11), MaxLengthValidator(11),
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
        # username = str(username)
        # if len(username) < 4:
        #     raise serializers.ValidationError(
        #         {'invalid username': "username is to small"})
        #
        # if username.isnumeric():
        #     raise serializers.ValidationError(
        #         {'invalid username': "username can not be a number"})

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


class TokenGeneralSerializer(serializers.Serializer):
    token_key = serializers.CharField(max_length=255, read_only=True)
    user_agent = serializers.CharField(max_length=255, read_only=True)
    created = serializers.DateTimeField(read_only=True)


class TokenSerializer(serializers.ModelSerializer):
    token_key = serializers.CharField(read_only=True)

    class Meta:
        model = AuthToken
        fields = ['token_key']


class UserLoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['username', 'password']


class SendOtpSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=255, write_only=True,
                                  validators=[MinLengthValidator(11), MaxLengthValidator(11),
                                              CoreValidation.phone_regx_validator()])


class OtpValidateSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=255, write_only=True, required=True)


class UserChangePassSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(max_length=255, required=True, )
    password = serializers.CharField(max_length=255, write_only=True, required=True, )
    password_repeat = serializers.CharField(max_length=255, write_only=True, required=True)

    class Meta:
        model = User
        fields = ['old_password', 'password', 'password_repeat']

    def validate(self, data):
        return validate_password_and_repeat_password(data)


class UserForgetPassSerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=255, required=True)
    phone = serializers.CharField(max_length=11, required=True, validators=[
        CoreValidation.phone_regx_validator(),
        MinLengthValidator(11), MaxLengthValidator(11),
    ])
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
        self.fields['token_keys'] = serializers.MultipleChoiceField(choices=self.tokens())

    def tokens(self):
        user_id = self.context.get('user_id')
        request = self.context.get('request')
        return [(row.token_key, str(row.created) + "-" + row.user_agent) for row in
                AuthToken.objects.only('token_key', 'user_agent', 'created').filter(user_id=user_id).all()]


class TokenUserSerializerSerializer(serializers.ModelSerializer):
    token_key = serializers.CharField(read_only=True)
    # user = UserSerializer(read_only=True)
    class Meta:
        model = AuthToken
        # fields = ['token_key', 'user_id', 'user' , 'created']
        fields = '__all__'