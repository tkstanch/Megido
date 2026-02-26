from django.urls import path
from . import views
from browser.views import launch_pyqt_browser

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
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),

    # Campaign URLs
    path('campaigns/', views.campaign_list, name='campaign_list'),
    path('campaigns/new/', views.campaign_start, name='campaign_start'),
    path('campaigns/<int:campaign_id>/', views.campaign_detail, name='campaign_detail'),
    path('campaigns/<int:campaign_id>/status/', views.campaign_status, name='campaign_status'),
    path('campaigns/<int:campaign_id>/pause/', views.campaign_pause, name='campaign_pause'),
    path('campaigns/<int:campaign_id>/resume/', views.campaign_resume, name='campaign_resume'),
    path('campaigns/<int:campaign_id>/results/', views.campaign_results, name='campaign_results'),
    path('campaigns/<int:campaign_id>/exploits/', views.campaign_exploits, name='campaign_exploits'),
    path('campaigns/<int:campaign_id>/export/', views.campaign_export, name='campaign_export'),

    # Exploit detail
    path('exploits/<int:result_id>/', views.exploit_detail, name='exploit_detail'),

    # Payload management
    path('payloads/import/', views.payload_import, name='payload_import'),
    path('payloads/effectiveness/', views.payload_effectiveness, name='payload_effectiveness'),
]
