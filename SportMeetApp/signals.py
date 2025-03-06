
from django.db.models.signals import pre_save
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.conf import settings
from django.contrib.auth.models import Group
from .models import VenueOwnerProfile
import logging

User = get_user_model()

@receiver(pre_save, sender=SocialAccount)
def set_google_user_active(sender, instance, **kwargs):
    if instance.provider == 'google':
        user = instance.user
        if not user.is_active:
            user.is_active = True  # Replace 'YourGroupName' with the desired group name
            group, _ = Group.objects.get_or_create(name='Customer')
            user.groups.add(group)
            user.save()
    # elif instance.provider == 'facebook':
    #     user = instance.user
    #     if not user.is_active:
    #         user.is_active = True # Replace 'YourGroupName' with the desired group name
    #         group, _ = Group.objects.get_or_create(name='Customer')
    #         user.groups.add(group)
    #         user.save()
    






logger = logging.getLogger("SportMeetApp")

@receiver(post_save, sender=VenueOwnerProfile)
def send_approval_email(sender, instance, **kwargs):
    if instance.is_approved:
        subject = "Your Venue Owner Profile has been Approved"
        message = f"Dear {instance.user.get_full_name()},\n\nYour venue owner profile has been approved. You now have staff privileges.\n\nBest regards,\nSportMeet Team"
        recipient_list = [instance.user.email]
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list)