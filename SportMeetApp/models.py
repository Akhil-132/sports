from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.db import models
from django.core.exceptions import ValidationError
from django.db.models import Avg
import uuid

# Email Verification
class EmailVerificationToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

# Customer Profile
class CustomerProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="customer_profile")
    phone = models.CharField(max_length=15, blank=True, null=True)
    profile_picture = models.ImageField(upload_to="profiles/", blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.get_full_name()


# Venue Owner Profile
class VenueOwnerProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="venue_owner_profile")
    phone = models.CharField(max_length=15, blank=True, null=True)
    profile_picture = models.ImageField(upload_to="profiles/", blank=True, null=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Owner: {self.user.get_full_name()} ({'Approved' if self.is_approved else 'Pending'})"

    def approve(self):
        """Approve the venue owner and grant staff permissions."""
        self.is_approved = True
        self.user.is_staff = True  # Grant staff privileges
        self.user.save()
        self.save()
class Sporttype(models.Model):
    name=models.CharField(max_length=255,null=True,blank=True)
    image=models.ImageField(blank=True,null=True,upload_to='court_images/')
    
    def __str__(self):
        return self.name
class Banner(models.Model):
    bannerimage = models.ImageField(upload_to='banners/', blank=True, null=True)
    
    def __str__(self):
        return self.bannerimage.url if self.bannerimage else "No Image"
    
    

    
# Venue Model
class Venue(models.Model):
    owner = models.ForeignKey(VenueOwnerProfile, on_delete=models.CASCADE, related_name="venues")
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    city=models.CharField(max_length=255,blank=True,null=True)
    area=models.CharField(max_length=255,blank=True,null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    image = models.ImageField(upload_to="venue_images/")
    google_maps_link = models.URLField(blank=True, null=True)
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    
    def average_rating(self):
        avg_rating = self.ratings.aggregate(avg_rating=Avg('rating'))['avg_rating']
        return round(avg_rating, 1) if avg_rating else 0



# Venue Images
class VenueImage(models.Model):
    venue = models.ForeignKey(Venue, on_delete=models.CASCADE, related_name="images")
    image = models.ImageField(upload_to="venue_images/")

    def __str__(self):
        return f"Image for {self.venue.name}"

# Court Model
class Court(models.Model):
    DURATION_CHOICES = [
        (30, "30 Minutes"),
        (60, "1 Hour"),
        (90, "1 Hour 30 Minutes"),
        (120, "2 Hours"),
    ]

    venue = models.ForeignKey(Venue, on_delete=models.CASCADE, related_name="courts")
    sport = models.ForeignKey(Sporttype, on_delete=models.CASCADE,related_name="courts")
    court_number = models.PositiveIntegerField()  # Unique identifier for each court
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    duration = models.PositiveIntegerField(choices=DURATION_CHOICES, default=30)  # half an hour default

    def __str__(self):
        return f"{self.sport.name} - Court {self.court_number} at {self.venue.name}"
    
    def generate_time_slots(self):
        """
        Generates slots dynamically using venue start/end time and court duration.
        This does NOT save anything in the DB. Just for use in templates/views.
        """
        slots = []
        start_time = datetime.combine(datetime.today(), self.venue.start_time)
        end_time = datetime.combine(datetime.today(), self.venue.end_time)

        while start_time + timedelta(minutes=self.duration) <= end_time:
            next_time = start_time + timedelta(minutes=self.duration)
            slots.append((start_time.time(), next_time.time()))
            start_time = next_time

        return slots


class CourtRequest(models.Model):
    DURATION_CHOICES = [
        (30, "30 Minutes"),
        (60, "1 Hour"),
        (90, "1 Hour 30 Minutes"),
        (120, "2 Hours"),
    ]

    venue = models.ForeignKey(Venue, on_delete=models.CASCADE)
    sport = models.ForeignKey(Sporttype, on_delete=models.CASCADE)
    court_count = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Add duration field here
    duration = models.PositiveIntegerField(choices=DURATION_CHOICES, default=30)  # Same choices as Court

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Create courts automatically with duration applied
        existing_courts = Court.objects.filter(venue=self.venue, sport=self.sport).count()

        for i in range(1, self.court_count + 1):
            Court.objects.create(
                venue=self.venue,
                sport=self.sport,
                court_number=existing_courts + i,  # Increment court numbers
                price=self.price,
                duration=self.duration  # Assign the selected duration to each court
            )

        self.delete()  # Remove request after processing

    def __str__(self):
        return f"{self.court_count} {self.sport.name} courts for {self.venue.name}"



class Rating(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="ratings")
    venue = models.ForeignKey("Venue", on_delete=models.CASCADE, related_name="ratings")
    rating = models.PositiveIntegerField(choices=[(i, i) for i in range(1, 6)])  # 1 to 5 stars
    review = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    

class Booking(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
        ('completed', 'Completed'),
    ]

    customer = models.ForeignKey(CustomerProfile, on_delete=models.CASCADE, related_name="bookings")
    venue = models.ForeignKey(Venue, on_delete=models.CASCADE, related_name="bookings")
    sport = models.ForeignKey(Sporttype, on_delete=models.CASCADE, related_name="bookings")
    court = models.ForeignKey(Court, on_delete=models.CASCADE, related_name="bookings")

    date = models.DateField()  # Date of booking
    start_time = models.TimeField()  # Selected slot start time
    end_time = models.TimeField()  # Selected slot end time
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['court', 'date', 'start_time', 'end_time']

    def __str__(self):
        return f"Booking for {self.sport.name} - {self.venue.name} - Court {self.court.court_number} on {self.date} from {self.start_time} to {self.end_time}"

    def clean(self):
        # Prevent double booking (ensure no overlaps for the same court, date and time slot)
        overlapping_booking = Booking.objects.filter(
            court=self.court,
            date=self.date,
            start_time__lt=self.end_time,
            end_time__gt=self.start_time,
            status__in=['pending', 'confirmed']  # Ignore cancelled or completed bookings
        ).exists()

        if overlapping_booking:
            raise ValidationError("This court is already booked for the selected time slot.")

    def save(self, *args, **kwargs):
        self.full_clean()  # Run validation before saving
        super().save(*args, **kwargs)



class ChatMessage(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name="sent_messages")
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name="received_messages")
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.sender.username} to {self.receiver.username}"
