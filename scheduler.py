import os
import django
from datetime import timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from django.utils import timezone

# ✅ Setup Django properly
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SportMeet.settings')

# ✅ Only set up Django when running standalone
if __name__ == "__main__":
    django.setup()

from SportMeetApp.models import Venue  # Import after setup

def update_booking_dates():
    """Update booking start and end dates for all venues."""
    today = timezone.now().date()
    for venue in Venue.objects.all():
        venue.start_date = today
        venue.end_date = today + timedelta(days=7)
        venue.save()
        print(f"Updated booking dates for {venue.name}: {venue.start_date} to {venue.end_date}")

scheduler = BackgroundScheduler()

def start():
    """Start the scheduler to update booking dates every day."""
    if not scheduler.running:  # Prevent duplicate schedulers
        scheduler.add_job(update_booking_dates, 'interval', days=1, start_date='2025-02-18')
        scheduler.start()

if __name__ == "__main__":
    start()
