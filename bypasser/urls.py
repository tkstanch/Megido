from django.urls import path
from . import views

app_name = 'bypasser'

urlpatterns = [
    path('', views.bypasser_dashboard, name='dashboard'),
    path('api/targets/', views.bypasser_targets, name='bypasser_targets'),
    path('api/targets/<int:target_id>/probe/', views.start_character_probe, name='start_character_probe'),
    path('api/sessions/<int:session_id>/results/', views.session_results, name='session_results'),
    path('api/sessions/<int:session_id>/test-bypass/', views.test_encoding_bypass, name='test_encoding_bypass'),
    path('api/sessions/<int:session_id>/bypasses/', views.bypass_results, name='bypass_results'),
    
    # Custom bypass techniques endpoints
    path('api/custom-techniques/', views.custom_techniques, name='custom_techniques'),
    path('api/custom-techniques/<int:technique_id>/', views.custom_technique_detail, name='custom_technique_detail'),
    path('api/custom-techniques/<int:technique_id>/test/', views.test_custom_technique, name='test_custom_technique'),
    path('api/sessions/<int:session_id>/use-custom/', views.use_custom_techniques, name='use_custom_techniques'),
    path('api/transformations/', views.get_available_transformations, name='available_transformations'),
    
    # Ready-made payloads endpoints
    path('api/payloads/', views.list_payloads, name='list_payloads'),
    path('api/payloads/<int:payload_id>/', views.get_payload, name='get_payload'),
    path('api/payloads/<int:payload_id>/transform/', views.transform_payload, name='transform_payload'),
    path('api/payloads/<int:payload_id>/fuzz/', views.fuzz_payload_api, name='fuzz_payload'),
    path('api/payloads/combine/', views.combine_payloads_api, name='combine_payloads'),
    path('api/payloads/categories/', views.get_payload_categories, name='payload_categories'),
    path('api/payloads/initialize/', views.initialize_payload_library, name='initialize_payloads'),
    path('api/sessions/<int:session_id>/inject-payloads/', views.inject_payload, name='inject_payload'),
]
