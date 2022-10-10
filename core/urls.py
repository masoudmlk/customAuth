from django.urls import path, include
from . import views
from pprint import pprint
from rest_framework_nested import routers


router = routers.DefaultRouter()

router.register('customauth', views.CustomAuthViewSet, basename='customauth')

urlpatterns = router.urls

pprint(urlpatterns)
