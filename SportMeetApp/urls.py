from django.urls import path
from . import views
from .views import *
from django.views.generic import TemplateView


app_name='SportMeetApp'

urlpatterns = [
    path('home/', views.home, name='home'),
    path('api/register-user/', RegisterUserView.as_view(), name='register-user'),
    path('register/', register_view, name='register'),
    path('registration_success/',registration_success, name='registration_success'),
    path('verify-email/<uuid:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', views.user_login, name='login'),
    path('logout/', user_logout, name='logout'),
    path('approval/', views.approval_page, name='approval'),
    path('api/venues/', VenueListView.as_view(), name='venue-list'),
    path('allvenues/', VenueAllListView.as_view(), name='allvenue-list'),
    path('api/sporttypes/', SporttypeListView.as_view(), name='sporttype-list'),
    path("api/search-venues/", search_venues, name="search_venues"),
    path("search-results/", search_results, name="search_results"),
    path('sports_venue', sports_venue, name='sports-venue'),
    path('venues/<int:venue_id>/', VenueDetailView.as_view(), name='venue-detail'),
    path('booking-view/<int:venue_id>/', booking_view, name='booking-view'),
    path('api/get_bookings/', GetBookingsView.as_view(), name='get_bookings'),
    path('api/bookings/', BookingCreateAPIView.as_view(), name='bookings'),
    # path('api/book/', book_venue, name='book_venue'),
    # path('api/check-availability/', check_availability, name='check_availability'),
    # path('api/courts/<int:venue_id>/<int:sport_id>/', get_courts_by_sport_and_venue, name="api_get_courts"),
    # path('api/available-dates/', available_dates, name='available_dates'),
    path('api/password-reset/', send_password_reset_email, name='password-reset'),
    path("api/password-reset-confirm/<uidb64>/<token>/", reset_password_confirm, name="password_reset_confirm"),
    path('password_reset/', password_reset_view, name='password_reset'),
    path('reset-password/<uidb64>/<token>/', password_reset_confirm_view, name='password-reset-form'),
    path('success/', success_page, name='success'),
    path('venues/<int:venue_id>/submit_review/', ReviewListCreateView.as_view(), name='submit_review'),
    path('test-emails/', test_booking_emails),
    path('api/location-suggestions/', location_suggestions, name='location-suggestions'),
    path('customer_chat/', views.customer_chat, name='customer_chat'),
    path('admin_chat/', views.admin_chat, name='admin_chat'),
    path('get_messages/', views.get_messages, name='get_messages'),
    path('send_message/', views.send_message, name='send_message'),
    path('get_messaged_customers/', views.get_messaged_customers, name='get_messaged_customers'),
    
]
    
    

    

    
