from django.urls import path, include
from pprint import pprint
from rest_framework_nested import routers
from core import views

router = routers.DefaultRouter()

router.register('custom-auth', views.UserAuthViewSet, basename='user-auth')
router.register('otp', views.OTPViewSet, basename='otp')
router.register('token', views.TokensViewSet, basename='token')

urlpatterns = router.urls

pprint(urlpatterns)
