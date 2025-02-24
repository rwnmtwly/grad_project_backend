from django.shortcuts import render


from rest_framework import (
    generics, status, views, permissions
    )
from rest_framework.response import Response

from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter, 
    OpenApiTypes,
    )

from .serializers import GoogleSocialAuthSerializer

# Create your views here.
class GoogleSocialAuthAPIView(generics.GenericAPIView):
    serializer_class = GoogleSocialAuthSerializer


    def post(self, request):
        """
        POST with "auth_token"
        send an idtoken from google to get user information
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = ((serializer.validated_data)['auth_token'])
        return Response(data, status=status.HTTP_200_OK)