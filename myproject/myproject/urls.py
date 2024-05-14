from django.contrib import admin
from django.urls import path, include
from submissions.views import redirect_to_submit

urlpatterns = [
    path('admin/', admin.site.urls),
    path('submit/', include('submissions.urls')),
    path('', redirect_to_submit, name='home')
]