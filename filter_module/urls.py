from django.urls import path
from filter_module import views

urlpatterns = [
  path('', views.index, name='index'),
  path('api/check', views.api_check, name='api_check'),
  path('api/logs', views.api_logs, name='api_logs'),
  path('api/stats', views.api_stats, name='api_stats')
]

