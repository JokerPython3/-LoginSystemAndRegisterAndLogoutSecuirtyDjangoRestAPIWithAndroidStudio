from django.urls import path
from rest_framework_simplejwt.views import(
TokenRefreshView,
TokenObtainPairView,
TokenVerifyView
)
from . import  views
urlpatterns = [
    path('api/token/',TokenObtainPairView.as_view(),name="token"),
    path('api/token/refresh/',TokenRefreshView.as_view(),name="token_refresh"),
    path('api/token/verify/',TokenVerifyView.as_view(),name="token_verify"),
    path('api/login/',views.login,name="login"),
    path('api/logout/',views.logout,name="logout"),
    path('api/register/',views.register,name="register"),
    # path('api/register/email/send_code',name="email_send_code"),
    # path('api/register/mobile/send_code',name="mobile_send_code"),
    # path('api/register/email/check_code/<code:str>',name="check_code"),
    # path('api/register/mobile/check_code/<code:str>',name="check_code"),
]