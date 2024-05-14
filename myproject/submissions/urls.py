from django.urls import path
from .views import submit_code, success, send_code

urlpatterns = [
    path('', submit_code, name='submit_code'),
    path('success/', success, name='success'),
    path('send_code/', send_code, name='send_code')
]