from django.core.mail import send_mail
from django.conf import settings

def send_booking_confirmation_email(user_email, user_name, venue_name):
    booking_date = "2025-03-15"  # Static date
    booking_time = "18:00"       # Static time

    subject = "Booking Confirmation"
    message = (
        f"Hi {user_name},\n\n"
        f"Your booking for {venue_name} is confirmed.\n\n"
        f"Booking Date: {booking_date}\n"
        f"Booking Time: {booking_time}\n\n"
        f"Thank you for choosing us!\n\n"
        f"Best regards,\nThe Venue Team"
    )
    send_mail(subject, message, settings.EMAIL_HOST_USER, [user_email])

def send_booking_reminder_email(user_email, user_name, venue_name):
    booking_date = "2025-03-15"  # Static date
    booking_time = "18:00"       # Static time

    subject = "Booking Reminder"
    message = (
        f"Hi {user_name},\n\n"
        f"This is a reminder for your upcoming booking at {venue_name}.\n\n"
        f"Booking Date: {booking_date}\n"
        f"Booking Time: {booking_time}\n\n"
        f"We look forward to welcoming you!\n\n"
        f"Best regards,\nThe Venue Team"
    )
    send_mail(subject, message, settings.EMAIL_HOST_USER, [user_email])
    
    
def send_verification_email(user, token):
    # Add a redirect parameter to the verification URL
    verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}/?redirect=/login/"
    
    subject = "Verify Your Email Address"
    message = f"""
    Hi {user.first_name},

    Thank you for registering. Please click the link below to verify your email address:

    {verification_url}

    If you did not register, please ignore this email.

    Regards,
    Your Team
    """
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
