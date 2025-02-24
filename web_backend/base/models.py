from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if username is None:
            raise ValueError('Users should have a username')
        if email is None:
            raise ValueError('Users should have an email')

        email = self.normalize_email(email)

        user = self.model(username=username, email=email)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise ValueError('Admins must have a password')
        user = self.create_user(username, email, password )
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return user
    

AUTH_PROVIDERS = { 'google': 'google', 'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=30, unique=True)
    email = models.EmailField(max_length=200, unique=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(max_length=255, null=False, blank=False, default=AUTH_PROVIDERS.get('email'))

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']


    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


