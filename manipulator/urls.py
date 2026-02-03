from django.urls import path
from . import views

app_name = 'manipulator'

urlpatterns = [
    path('', views.manipulator_home, name='home'),
    path('vulnerability/<int:vuln_id>/', views.vulnerability_detail, name='vulnerability_detail'),
    path('craft/', views.craft_payload, name='craft_payload'),
    path('encode-ajax/', views.encode_payload_ajax, name='encode_payload_ajax'),
    path('library/', views.payload_library, name='payload_library'),
    path('add-payload/', views.add_payload, name='add_payload'),
    path('crafted/', views.crafted_payloads, name='crafted_payloads'),
    path('tricks/', views.manipulation_tricks, name='manipulation_tricks'),
    path('encoding-tools/', views.encoding_tools, name='encoding_tools'),
]
