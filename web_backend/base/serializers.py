from rest_framework import serializers
from .models import User
from .utils import Util
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError #smart_str, force_str, smart_bytes: these are to meke sure we're sending conventional data so it enables us to enforce Unicode
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=70, min_length=7, write_only=True)
    default_error_messages={
        'username': 'The user name should only contain letters and numbers'
    }
    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def validate(self, attrs):
        username = attrs.get('username','')
        email = attrs.get('email','')
        if not username.isalnum():
            raise serializers.ValidationError(self.default_error_messages)
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=700)

    class Meta:
        model= User
        fields= ['token']
    

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=200, min_length=7)
    password = serializers.CharField(max_length=70, min_length=7, write_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        
        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model= User
        fields= ['email', 'password', 'tokens']
        
    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, Try again.')
        if not user.is_active:
            raise AuthenticationFailed('This account is not active. Please, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('This email is not verified')
        
        return {
            'email': user.email,
            'tokens': user.tokens
        }

        return super().validate(attrs)


class RequestPasswordResetEmailSerializer(serializers.Serializer):

    email = serializers.EmailField(max_length=200, min_length=7)

    class Meta:
        fields= ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=7, max_length=70 , write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            
            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        
        return super().validate(attrs)