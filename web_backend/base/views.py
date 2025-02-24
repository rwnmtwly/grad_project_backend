from django.shortcuts import render
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.conf import settings
from django.utils.encoding import (
    smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
    ) #smart_str, force_str, smart_bytes: these are to meke sure we're sending conventional data so it enables us to enforce Unicode
from django.utils.http import (
    urlsafe_base64_encode, urlsafe_base64_decode
    )
from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter, 
    OpenApiTypes,
    )
from rest_framework import (
    generics, status, views, permissions
    )
from rest_framework.response import Response
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
import jwt
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    RegisterSerializer,
    EmailVerificationSerializer,
    LoginSerializer,
    RequestPasswordResetEmailSerializer,
    SetNewPasswordSerializer,
    )
from .models import User
from .utils import Util
from .renderers import UserRenderer
# Create your views here.

class RegisterUserAPIView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    @extend_schema(
        summary="User Registration",
        description="Registers a new user and returns user data.",
        request=RegisterSerializer,
        responses={201: RegisterSerializer},
    )

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data

        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('verify-email')
        absolute_url = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi,'+user.username+' Use This Link Below to Verify Your Email \n'+absolute_url
        data = {'email_body': email_body, 'email_to': user.email, 'email_subject':'Verify Your Email'}
        Util.send_email(data)
        
        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class=EmailVerificationSerializer
    token_param_config =OpenApiParameter(name='token',  
                                         location=OpenApiParameter.QUERY, 
                                         description='The token received in the email for verification.', 
                                         type=OpenApiTypes.STR, 
                                         required=True)


    @extend_schema(
        summary="Verify Email",
        description="This endpoint verifies a user's email using a token passed as a query parameter.",
        parameters=[token_param_config],
    )

    
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully Activated'}, status=status.HTTP_200_OK)
        
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_200_OK)


class LoginAPIVIEW(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

  
class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = RequestPasswordResetEmailSerializer
    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user= User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            """
            PasswordResetTokenGenerator():
            this class will take care of knowing if the user changed their password, it can invalidate this token
            in that way another user doesn't come and use the same resetpasswordtoken
            """
            token = PasswordResetTokenGenerator().make_token(user) #to make a token fot the user

            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absolute_url = 'http://'+current_site+relativeLink
            email_body = 'Hi, \n Use This Link Below to Reset Your Password \n'+absolute_url
            data = {'email_body': email_body, 'email_to': user.email, 'email_subject':'Reset Your Password'}
            Util.send_email(data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheck(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    def get(self, request, uidb64, token):
        try:
            id=smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid. Please, request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success':True, 'message':'Valid Credentials', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)


        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid. Please, request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIVIEW(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer 

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({'success':True, 'message': 'Password successfully reset'}, status=status.HTTP_200_OK)