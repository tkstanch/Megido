from django.urls import path
from . import views, api
from browser.views import launch_pyqt_browser

app_name = 'interceptor'

urlpatterns = [
    # UI Views
    path('', views.interceptor_dashboard, name='dashboard'),
    
    # Legacy API endpoints
    path('api/status/', views.interceptor_status, name='interceptor_status'),
    path('api/intercepted/', views.list_intercepted, name='list_intercepted'),
    path('api/intercepted/<int:request_id>/', views.intercepted_detail, name='intercepted_detail'),
    
    # New mitmproxy integration API endpoints
    path('api/request/', api.receive_request, name='receive_request'),
    path('api/response/', api.receive_response, name='receive_response'),
    path('api/payload-rules/active/', api.get_active_payload_rules, name='active_payload_rules'),
    path('api/payload-rules/', api.PayloadRuleListCreateView.as_view(), name='payload_rules_list'),
    path('api/payload-rules/<int:pk>/', api.PayloadRuleDetailView.as_view(), name='payload_rule_detail'),
    path('api/history/', api.InterceptHistoryView.as_view(), name='intercept_history'),
    path('api/inject/', api.manual_inject, name='manual_inject'),
    path('api/request/<int:request_id>/', api.request_detail, name='request_detail_api'),
    path('api/launch-desktop-browser/', launch_pyqt_browser, name='launch_desktop_browser'),
]
