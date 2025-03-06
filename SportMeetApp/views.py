
from datetime import date
import json
from django.utils import timezone
import re
from django.urls import reverse
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, status,permissions
from rest_framework.decorators import api_view,permission_classes
from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth import login, logout, authenticate
from .forms import CustomerRegistrationForm, VenueOwnerRegistrationForm
from django.contrib.auth.forms import AuthenticationForm
from .models import CustomerProfile, VenueOwnerProfile
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.contrib.auth.models import User,Group
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import *
from .models import *
from django.db.models import Q
import threading
from django.utils.decorators import method_decorator
import requests
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes, force_str
from rest_framework.permissions import AllowAny
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils.dateparse import parse_date
from .utils.email_utils import send_booking_confirmation_email, send_booking_reminder_email
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

def test_booking_emails(request):
    user_email = 'avinashnukathoti357@gmail.com'
    user_name = 'Avinash'
    venue_name = 'Grand Palace'

    # Send both emails for testing purposes
    send_booking_confirmation_email(user_email, user_name, venue_name)
    send_booking_reminder_email(user_email, user_name, venue_name)

    return JsonResponse({'status': 'Test emails sent successfully'})

def home(request):
    banner = Banner.objects.first()
    venue = Venue.objects.all()
    sports=Sporttype.objects.all()
    
    context = {
        'banner_image': banner.bannerimage.url if banner and banner.bannerimage else None,
        'sports': list(sports),
        'venue': venue
    }
    return render(request, "index.html", context)



def approval_page(request):
    return render(request, "approval.html")

# def validate_password(password):
#     """
#     Validate password to ensure it meets the following criteria:
#     - At least 8 characters long
#     - Contains at least one uppercase letter
#     - Contains at least one digit
#     - Contains at least one special character
#     """
#     if len(password) < 8:
#         return False, "Password must be at least 8 characters long."

#     if not re.search(r'[A-Z]', password):
#         return False, "Password must contain at least one uppercase letter."

#     if not re.search(r'[0-9]', password):
#         return False, "Password must contain at least one digit."

#     if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
#         return False, "Password must contain at least one special character."

#     return True, "Password is valid."

def sports_venue(request):
    return render(request, "sportspage.html")



class VerifyEmailView(APIView):
    def get(self, request, token):
        try:
            # Find the token in the database
            token_obj = EmailVerificationToken.objects.get(token=token)
            user = token_obj.user

            # Optional: Check if the user is already verified
            if user.is_active:
                return Response({"message": "Email already verified."}, status=status.HTTP_400_BAD_REQUEST)

            # Activate the user
            user.is_active = True
            user.save()

            # Delete the token (it's no longer needed)
            token_obj.delete()

            # Optional: Set a "verified" flag on the user profile (if you have one)
            # if hasattr(user, 'profile'):
            #     user.profile.email_verified = True
            #     user.profile.save()

            return redirect(reverse('SportMeetApp:login') + '?verified=1')

        except EmailVerificationToken.DoesNotExist:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
      
class RegisterUserView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            # Include the success page URL in the response
            return Response({
                "success": "Registration successful. Please check your email to verify your account.",
                "redirect_url": reverse('SportMeetApp:registration_success')  # URL for the success page
            }, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


  
def register_view(request):
    return render(request, "register.html")
    
def registration_success(request):
    return render(request, "register_success.html")
    
    
    
# def register_user(request):
#     if request.method == "POST":
#         # Get form data
#         first_name = request.POST.get("first_name")
#         last_name = request.POST.get("last_name")
#         username = request.POST.get("username")
#         email = request.POST.get("email")
#         phone = request.POST.get("phone")
#         password = request.POST.get("password")
#         confirm_password = request.POST.get("confirm_password")
#         is_owner = request.POST.get("is_owner") == "true"  # Checkbox value

#         # Password confirmation check
#         if password != confirm_password:
#             return JsonResponse({"error": "Passwords do not match"}, status=400)

#         # Check if username or email already exists
#         if User.objects.filter(username=username).exists():
#             return JsonResponse({"error": "Username already taken"}, status=400)

#         if User.objects.filter(email=email).exists():
#             return JsonResponse({"error": "Email already registered"}, status=400)

#         # Create user
#         user = User.objects.create_user(username=username, email=email, password=password)
#         user.first_name = first_name
#         user.last_name = last_name

#         if is_owner:
#             user.is_staff = True  # Give staff status to owners
#         user.save()

#         # Create appropriate profile
#         if is_owner:
#             VenueOwnerProfile.objects.create(user=user, phone=phone)
#             return JsonResponse({
#                 "success": "Registration successful", 
#                 "redirect_url": "/approval/"  # Send URL for approval page
#             }, status=201)
#         else:
#             CustomerProfile.objects.create(user=user, phone=phone)
#             return JsonResponse({
#                 "success": "Registration successful", 
#                 "redirect_url": '/login/'
#             }, status=201)

     

#     return render(request, "register.html")




def user_login(request):
    if request.method == "POST":
        email = request.POST.get('email')  # Get email from the form
        password = request.POST.get('password')  # Get password from the form

        # Check if a user with the provided email exists
        try:
            user = User.objects.get(email=email)  # Fetch user by email
        except User.DoesNotExist:
            return HttpResponse("User with this email does not exist.")

        # Authenticate the user
        user = authenticate(request, username=user.username, password=password)

        if user is not None:
            # Check if the user is a venue owner
            try:
                venue_owner_profile = VenueOwnerProfile.objects.get(user=user)
                if not venue_owner_profile.is_approved:
                    # If not approved, show a message
                    return redirect("SportMeetApp:approval")  # Redirect to the approval page
                else:
                    # If approved, redirect to the dashboard
                    login(request, user)
                    group = Group.objects.get(name='owner')
                    user.groups.add(group)
                    return redirect(reverse('admin:index'))  # Redirect to the dashboard page
            except VenueOwnerProfile.DoesNotExist:
                # If the user is not a venue owner, check if they are a customer
                try:
                    customer_profile = CustomerProfile.objects.get(user=user)
                    # If the user is a customer, redirect to the home page
                    login(request, user)
                    return redirect("SportMeetApp:home")  # Redirect to the home page
                except CustomerProfile.DoesNotExist:
                    # If the user is neither a venue owner nor a customer, handle accordingly
                    return HttpResponse("User profile not found.")
        else:
            return HttpResponse("Invalid credentials.")

    return render(request, "login.html")



def user_logout(request):
    logout(request)
    return redirect("SportMeetApp:home")  # Redirect to home after logout





class VenueListView(APIView):
    def get(self, request):
        venues = Venue.objects.all()[:6]  # Get the first 6 venues
        serializer = VenueSerializer(venues, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class VenueAllListView(APIView):
    def get(self, request):
        venues = Venue.objects.all()  # Get the first 6 venues
        serializer = VenueSerializer(venues, many=True)
        
        context = {
            'venues': serializer.data,
        }
        return render(request, 'venues.html', context)
        
    



class VenueDetailView(APIView):
    def get(self, request, venue_id):
        venue = get_object_or_404(Venue.objects.prefetch_related('images', 'courts', 'ratings'), id=venue_id)
        serializer = VenueSerializer(venue)

        venue_images = venue.images.all()
        venue_courts = venue.courts.values('sport__id', 'sport__name', 'sport__image').distinct()
        

        # Fetch reviews directly
        reviews = venue.ratings.all()

        context = {
            'venue': venue,
            'venue_images': venue_images,
            'venue_courts': venue_courts,
            'reviews': reviews,  # Pass reviews separately
        }
        return render(request, 'sportspage.html', context)
    
    
class SporttypeListView(APIView):
    def get(self, request):
        sporttypes = Sporttype.objects.all() # Get the first 6 sport types
        serializer = SporttypeSerializer(sporttypes, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    



@api_view(["GET"])
def search_venues(request):
    """
    Search venues based on a single location input (city, area, or address).
    Also filters by sport type and date if provided.
    """
    location = request.GET.get("location", "").strip()  # Single location field
    sporttype = request.GET.get("sporttype", "").strip()
    date = request.GET.get("date", "").strip()  # Expected format: YYYY-MM-DD

    venues = Venue.objects.all()

    # Filter by location (matches city, area, or address)
    if location:
        venues = venues.filter(
            Q(city__icontains=location) |
            Q(area__icontains=location) |
            Q(address__icontains=location)
        )

    # Filter by sport type (linked to Court model via sports relationship)
    if sporttype:
        venues = venues.filter(courts__sport__name__icontains=sporttype)

    # Filter by date
    if date:
        try:
            search_date = datetime.strptime(date, "%Y-%m-%d").date()
            venues = venues.filter(start_date__lte=search_date, end_date__gte=search_date)
        except ValueError:
            return Response({"error": "Invalid date format. Use YYYY-MM-DD"}, status=400)

    venues = venues.distinct()

    serializer = VenueSerializer(venues, many=True)
    return Response(serializer.data, status=200)



def search_results(request):
    """
    Fetch search parameters and call the API to get search results.
    Handles location input which could be city, area, or address.
    """
    location = request.GET.get("location", "").strip()  # Single location field
    sporttype = request.GET.get("sporttype", "").strip()
    date = request.GET.get("date", "").strip()

    # Build API URL with location (can match against city, area, or address on the API side)
    api_url = f"http://127.0.0.1:8000/api/search-venues/?sporttype={sporttype}&date={date}&location={location}"
   

    # Append location if provided
    if location:
        api_url += f"&location={location}"

   

    try:
        response = requests.get(api_url)
        results = response.json() if response.status_code == 200 else []
    except Exception as e:
        results = {"error": "Could not fetch results."}

    return render(request, "search_result.html", {"results": results})



@api_view(['GET'])
def location_suggestions(request):
    query = request.GET.get('q', '').strip()

    if not query:
        return Response([])

    # Query distinct areas and cities matching the query
    venues = Venue.objects.filter(
        Q(area__icontains=query) | Q(city__icontains=query)
    ).values_list('area', 'city').distinct()

    # Combine area & city into one string per venue
    suggestions = []
    for area, city in venues:
        if area and city:
            suggestions.append(f"{area}, {city}")
        elif area:
            suggestions.append(area)
        elif city:
            suggestions.append(city)

    # Remove duplicates (in case same area-city pair appears more than once)
    suggestions = list(set(suggestions))

    return Response(suggestions)


def success_page(request):
    return render(request, "success.html")

# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def book_venue(request):
#     customer_profile = request.user.customer_profile
#     data = request.data.copy()
#     data['customer'] = customer_profile.id

#     # Extract required fields
#     court_id = data.get('court')  # Ensure this matches the frontend
#     time_slot_id = data.get('start_time')  # Ensure this matches the frontend
#     date = data.get('date')
#     duration = data.get('duration')

#     # Validate required fields
#     if not (court_id and time_slot_id and date and duration):
#         return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

#     # Convert date to a date object
#     try:
#         date = datetime.strptime(date, "%Y-%m-%d").date()
#     except ValueError:
#         return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

#     # Fetch Court and TimeSlot instances
#     try:
#         court = Court.objects.get(id=court_id)
#         time_slot = TimeSlot.objects.get(id=time_slot_id)
#     except (Court.DoesNotExist, TimeSlot.DoesNotExist):
#         return Response({"error": "Invalid court or time slot"}, status=status.HTTP_400_BAD_REQUEST)

#     # Calculate end_time dynamically
#     start_time = time_slot.time_slot
#     end_time = (datetime.combine(date, start_time) + timedelta(hours=int(duration))).time()

#     # Check for overlapping bookings
#     conflicting_bookings = Booking.objects.filter(
#         court=court,
#         date=date,
#         start_time__lt=end_time,
#         end_time__gt=start_time
#     )

#     if conflicting_bookings.exists():
#         return Response(
#             {"error": "This time slot is already booked. Please select a different time."},
#             status=status.HTTP_400_BAD_REQUEST
#         )

#     # Proceed with saving if no conflicts
#     data['court'] = court.id
#     data['start_time'] = start_time
#     data['end_time'] = end_time
#     serializer = VenueBookingSerializer(data=data)
#     if serializer.is_valid():
#         serializer.save()
#         return redirect('SportMeetApp:success')
#         # return Response({"message": "Booking successful", "booking": serializer.data}, status=status.HTTP_201_CREATED)

#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def check_availability(request):
#     court_id = request.GET.get('court')
#     date = request.GET.get('date')
#     start_time = request.GET.get('start_time')
#     duration = int(request.GET.get('duration', 1))  # Default to 1 hour if missing

#     if not court_id or not start_time or not date:
#         return JsonResponse({"error": "Missing required parameters"}, status=400)

#     try:
#         court = Court.objects.get(id=court_id)
#     except Court.DoesNotExist:
#         return JsonResponse({"error": "Invalid court"}, status=400)

#     parsed_date = parse_date(date)
#     start_time_obj = datetime.strptime(start_time, "%H:%M").time()
#     end_time_obj = (datetime.combine(parsed_date, start_time_obj) + timedelta(hours=duration)).time()

#     # **Check for overlapping bookings**
#     conflicting_bookings = Booking.objects.filter(
#         court=court,
#         date=parsed_date
#     ).filter(
#         start_time__lt=end_time_obj,  # Existing booking starts before our requested end time
#         end_time__gt=start_time_obj   # Existing booking ends after our requested start time
#     )

#     if conflicting_bookings.exists():
#         return JsonResponse({
#             "available": False,
#             "message": f"This court is already booked between {start_time_obj.strftime('%I:%M %p')} and {end_time_obj.strftime('%I:%M %p')}.",
#         })

#     return JsonResponse({"available": True})



# @api_view(['GET'])
# def get_courts_by_sport_and_venue(request, venue_id, sport_id):
#     """API to get courts based on selected venue and sport."""
#     courts = Court.objects.filter(venue_id=venue_id, sport_type__id=sport_id)
#     serializer = CourtSerializer(courts, many=True)
#     return Response(serializer.data)

# @api_view(['GET'])
# def available_dates(request):
#     venue_id = request.GET.get('venue_id')

#     if not venue_id:
#         return Response({"error": "venue_id is required"}, status=status.HTTP_400_BAD_REQUEST)

#     try:
#         venue = Venue.objects.get(id=venue_id)
#     except Venue.DoesNotExist:
#         return Response({"error": "Venue not found"}, status=status.HTTP_404_NOT_FOUND)

#     # Calculate available dates within the venue's start_date and end_date
#     today = date.today()
#     available_dates = []
#     current_date = venue.start_date
#     while current_date <= venue.end_date:
#         if current_date >= today:  # Only include future dates
#             available_dates.append(current_date)
#         current_date += timedelta(days=1)

#     # Convert dates to strings for JSON serialization
#     available_dates_str = [d.strftime("%Y-%m-%d") for d in available_dates]

#     return Response({
#         "venue_id": venue_id,
#         "available_dates": available_dates_str,
#     })
    

@api_view(["POST"])
def send_password_reset_email(request):
    email = request.data.get("email")

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)

    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    reset_url = request.build_absolute_uri(reverse("SportMeetApp:password_reset_confirm", args=[uid, token]))

    # Send Email
    send_mail(
        "Password Reset Request",
        f"Click the link to reset your password: {reset_url}",
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )

    return Response({"success": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)

@api_view(["GET", "POST"])
def reset_password_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        return Response({"error": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)

    if not default_token_generator.check_token(user, token):
        return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

    # Render the HTML form when accessed via GET
    if request.method == "GET":
        return render(request, "password_reset_confirm.html", {"uidb64": uidb64, "token": token})

    # Handle password reset submission via POST
    new_password = request.data.get("new_password")
    confirm_password = request.data.get("confirm_password")

    if not new_password or not confirm_password:
        return Response({"error": "Both password fields are required."}, status=status.HTTP_400_BAD_REQUEST)

    if new_password != confirm_password:
        return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

    # Optional: Check password strength
    if len(new_password) < 6:
        return Response({"error": "Password must be at least 6 characters long."}, status=status.HTTP_400_BAD_REQUEST)

    user.password = make_password(new_password)
    user.save()

    return Response({"success": "Password has been reset successfully."}, status=status.HTTP_200_OK)

def password_reset_view(request):
    return render(request, "password_reset.html")

def password_reset_confirm_view(request, uidb64, token):
    """Render password reset confirmation page with UID and token."""
    context = {"uidb64": uidb64, "token": token}
    return render(request, "password_reset_confirm.html", context)



 
class ReviewListCreateView(generics.ListCreateAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        venue_id = self.kwargs.get("venue_id")
        return Rating.objects.filter(venue_id=venue_id)

    def perform_create(self, serializer):
        venue_id = self.kwargs.get("venue_id")
        venue = get_object_or_404(Venue, id=venue_id)
        serializer.save(user=self.request.user, venue=venue)  # Pass venue directly
        


@login_required
def customer_chat(request):
    admin_user = User.objects.filter(is_superuser=True).first()  # Assuming one admin
    return render(request, 'customer_chat.html', {'admin_user': admin_user})


@login_required
def admin_chat(request):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    customers = User.objects.filter(is_superuser=False)  # Non-admin users
    return render(request, 'admin_chat.html', {'customers': customers})





@csrf_exempt
@login_required
def get_messages(request):
    user = request.user

    if user.is_superuser:
        # Admin gets messages for a selected customer (keep this logic)
        other_user_id = request.GET.get('other_user_id')
        other_user = get_object_or_404(User, id=other_user_id)
    else:
        # Customer gets messages only with the admin
        other_user = User.objects.filter(is_superuser=True).first()
        if not other_user:
            return JsonResponse({'error': 'Admin not found'}, status=400)

    messages = ChatMessage.objects.filter(
        (models.Q(sender=user) & models.Q(receiver=other_user)) |
        (models.Q(sender=other_user) & models.Q(receiver=user))
    ).order_by('timestamp')

    data = [
        {
            'sender': msg.sender.username,
            'message': msg.message,
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
        for msg in messages
    ]
    return JsonResponse(data, safe=False)



@csrf_exempt
@login_required
def send_message(request):
    if request.method == 'POST':
        sender = request.user
        
        # Determine the receiver based on the user type
        if sender.is_superuser:
            # Admin sends message to a selected customer
            receiver_id = request.POST.get('receiver_id')
            if not receiver_id:
                return JsonResponse({'error': 'Receiver ID is required for admin'}, status=400)
            receiver = get_object_or_404(User, id=receiver_id)
        else:
            # Customer sends message to the admin
            receiver = User.objects.filter(is_superuser=True).first()
            if not receiver:
                return JsonResponse({'error': 'Admin not found'}, status=400)

        message = request.POST.get('message')
        if not message:
            return JsonResponse({'error': 'Message is required'}, status=400)

        ChatMessage.objects.create(sender=sender, receiver=receiver, message=message)
        return JsonResponse({'status': 'Message sent'})
    
    
    
@login_required
def get_messaged_customers(request):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Unauthorized'}, status=403)

    # Get unique customers who have exchanged messages with the admin
    customer_ids = ChatMessage.objects.filter(
        Q(sender=request.user) | Q(receiver=request.user)
    ).values_list('sender_id', 'receiver_id').distinct()

    # Flatten the list and exclude the admin's ID
    unique_ids = set()
    for sender_id, receiver_id in customer_ids:
        if sender_id != request.user.id:
            unique_ids.add(sender_id)
        if receiver_id != request.user.id:
            unique_ids.add(receiver_id)

    # Fetch customer details
    customers = User.objects.filter(id__in=unique_ids, is_superuser=False)
    data = [{'id': customer.id, 'username': customer.username} for customer in customers]

    return JsonResponse(data, safe=False)









def booking_view(request, venue_id):
    venue = get_object_or_404(Venue, id=venue_id)

    # Handle selected sport (filtering courts)
    selected_sport_id = request.GET.get('sport_id')
    if selected_sport_id:
        try:
            selected_sport_id = int(selected_sport_id)
        except (ValueError, TypeError):
            selected_sport_id = None

    # Fetch courts, optionally filtering by sport
    courts_query = Court.objects.filter(venue=venue).select_related('sport')
    if selected_sport_id:
        courts_query = courts_query.filter(sport_id=selected_sport_id)

    # Order courts by court_number
    courts = courts_query.order_by('court_number')

    # Fetch distinct sports available at the venue (for dropdown filter)
    distinct_sports = Sporttype.objects.filter(courts__venue=venue).distinct()

    # Collect and deduplicate all available time slots across all courts
    time_slots = set()
    for court in courts:
        slots = court.generate_time_slots()
        for start, _ in slots:
            time_slots.add(start.strftime('%I:%M %p'))  # Format as '06:00 AM'

    # Convert to sorted list using proper 24-hour time conversion
    def convert_to_24hr(time_str):
        return datetime.strptime(time_str, "%I:%M %p")

    time_slots = sorted(time_slots, key=convert_to_24hr)

    # Handle selected date (default to today, ensure valid date)
    selected_date_str = request.GET.get('date', date.today().isoformat())
    selected_date = parse_date(selected_date_str) or date.today()

    # Fetch bookings for the selected date
    bookings = Booking.objects.filter(
        court__venue=venue,
        date=selected_date
    ).select_related('court')

    # Create a map of booked slots (time -> [court_numbers])
    booked_slots = {}
    for booking in bookings:
        slot_time = booking.start_time.strftime('%I:%M %p')
        if slot_time not in booked_slots:
            booked_slots[slot_time] = []
        booked_slots[slot_time].append(booking.court.court_number)

    # Convert courts to JSON-friendly data
    courts_data = [
        {
            'court_number': court.court_number,
            'sport_id': court.sport.id,
            'sport_name': court.sport.name,
            'price': float(court.price),  # Convert Decimal to float for JSON
            'duration': court.duration
        }
        for court in courts
    ]

    context = {
        'venue': venue,
        'time_slots_json': json.dumps(time_slots),
        'courts_json': json.dumps(courts_data),
        'booked_slots_json': json.dumps(booked_slots),
        'distinct_sports': distinct_sports,
        'selected_date': selected_date.isoformat(),
        'selected_sport_id': selected_sport_id,
        'today': date.today().isoformat(),  # For datepicker `min`
        'max_date': venue.end_date.isoformat() if venue.end_date else None  # For datepicker `max`
    }

    return render(request, 'booking.html', context)



class GetBookingsView(APIView):
    def get(self, request, *args, **kwargs):
        # Get the selected date and sport_id from the request
        selected_date_str = request.query_params.get('date')
        sport_id = request.query_params.get('sport_id')
        print(f"Selected Date: {selected_date_str}, Sport ID: {sport_id}") 

        # Parse the selected date
        try:
            selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            return Response({'error': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch all courts for the selected sport
        courts = Court.objects.filter(sport_id=sport_id).values_list('court_number', flat=True)
        print(f"Courts for Sport ID {sport_id}: {list(courts)}")

        # Fetch bookings for the selected date and sport
        bookings = Booking.objects.filter(
            date=selected_date,
            court__sport_id=sport_id,  # Filter by sport
            status__in=['pending', 'confirmed']  # Only consider active bookings
        ).select_related('court')

        # Create a map of booked slots (time -> [court_numbers])
        booked_slots = {}
        for booking in bookings:
            start_time = booking.start_time
            end_time = booking.end_time
            print(f"Booking: Court {booking.court.court_number}, Start: {start_time}, End: {end_time}")  # Debugging

            # Generate all time slots between start_time and end_time
            current_time = start_time
            while current_time < end_time:
                slot_time = current_time.strftime('%I:%M %p')
                if slot_time not in booked_slots:
                    booked_slots[slot_time] = []
                booked_slots[slot_time].append(booking.court.court_number)
                current_time = (datetime.combine(selected_date, current_time) + timedelta(minutes=30)).time()

        # Return the booked slots as JSON
        return Response({'booked_slots': booked_slots}, status=status.HTTP_200_OK)





class BookingCreateAPIView(APIView):
    def post(self, request, *args, **kwargs):
        print("Received data:", request.data)  # Debugging

        try:
            customer_profile = CustomerProfile.objects.get(user=request.user)
        except CustomerProfile.DoesNotExist:
            return Response({'error': 'Customer profile not found'}, status=status.HTTP_400_BAD_REQUEST)

        mutable_data = request.data.copy()
        mutable_data['customer'] = customer_profile.id  # Inject customer id from logged-in user

        # Validate and save the booking
        serializer = BookingSerializer(data=mutable_data)
        if serializer.is_valid():
            try:
                # Check for overlapping bookings
                court = Court.objects.get(id=mutable_data['court'])
                overlapping_bookings = Booking.objects.filter(
                    court=court,
                    date=mutable_data['date'],
                    start_time__lt=mutable_data['end_time'],
                    end_time__gt=mutable_data['start_time'],
                    status__in=['pending', 'confirmed']  # Ignore cancelled or completed bookings
                ).exists()

                if overlapping_bookings:
                    return Response({'error': 'This court is already booked for the selected time slot.'}, status=status.HTTP_400_BAD_REQUEST)

                serializer.save()
                print("Booking saved:", serializer.data)  # Debugging
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Court.DoesNotExist:
                return Response({'error': 'Court not found'}, status=status.HTTP_400_BAD_REQUEST)
            except ValidationError as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            print("Serializer errors:", serializer.errors)  # Debugging
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)