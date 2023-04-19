from django.urls import path
from . import views

urlpatterns = [
    path('hello/', views.home, name='home'),
    path('register/', views.home2, name='home2'),
]
