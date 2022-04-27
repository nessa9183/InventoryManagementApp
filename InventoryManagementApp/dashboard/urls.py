from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('logout', views.signOut, name='signOut'),
    path(r'^ajax/store/$', views.store, name='store'),
    path(r'^ajax/refresh/$', views.getData, name='refresh')
]