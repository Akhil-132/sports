# serializers.py
from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from rest_framework import serializers
from django.core.mail import send_mail
from .utils.email_utils import send_verification_email


User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    phone = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    is_owner = serializers.BooleanField(write_only=True)

    class Meta:
        model = User
        fields = ["first_name", "last_name","username", "email", "phone", "password", "confirm_password", "is_owner"]

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Username already taken.")
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("Email already registered.")
        return data

    def create(self, validated_data):
        phone = validated_data.pop('phone')
        is_owner = validated_data.pop('is_owner')
        validated_data.pop('confirm_password')
        
        validated_data['is_active'] = False
        user = User.objects.create_user(**validated_data)

        if is_owner:
            user.is_staff = True
        user.save()

        if is_owner:
            VenueOwnerProfile.objects.create(user=user, phone=phone)
        else:
            CustomerProfile.objects.create(user=user, phone=phone)

        # Create email verification token
        token = EmailVerificationToken.objects.create(user=user)

        # Send email verification
       
        send_verification_email(user, token.token)

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]



class SporttypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sporttype
        fields = ['id', 'name', 'image']

class VenueImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = VenueImage
        fields = ['image']
        
class ReviewSerializer(serializers.ModelSerializer):

    user = serializers.StringRelatedField(read_only=True)
 
    class Meta:

        model = Rating

        fields = ['id', 'user', 'rating', 'review', 'created_at']
 
        
class VenueSerializer(serializers.ModelSerializer):
    images = VenueImageSerializer(many=True, read_only=True)
    average_rating = serializers.SerializerMethodField()
    reviews = ReviewSerializer(many=True, read_only=True)
    class Meta:
        model = Venue
        fields = '__all__'
        
    def get_average_rating(self, obj):
        return obj.average_rating()
        
class CourtSerializer(serializers.ModelSerializer):
    class Meta:
        model = Court
        fields = ['id', 'court_no', 'price']
        

      

class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ['id', 'customer', 'venue', 'sport', 'court', 'date', 'start_time', 'end_time', 'price', 'status']


 
 