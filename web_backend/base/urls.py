from django.urls import path, include
from . import views

urlpatterns = [
    path('register/', views.RegisterUserAPIView().as_view(), name="register"),
    path('verify-email/', views.VerifyEmail().as_view(), name="verify-email"),
    path('login/',views.LoginAPIVIEW().as_view(), name= "login"),
    path('request-reset-email/', views.RequestPasswordResetEmail().as_view(), name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/', views.PasswordTokenCheck().as_view(), name="password-reset-confirm"),
    path('password-reset-complete/', views.SetNewPasswordAPIVIEW().as_view(), name="password-reset-complete")

]