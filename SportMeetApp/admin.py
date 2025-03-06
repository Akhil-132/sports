from django.contrib import admin
from django import forms
from .models import *
from django.utils import timezone


class VenueImageInline(admin.StackedInline):
    model = VenueImage
    extra = 1



class CourtInline(admin.StackedInline):
    model = Court
    extra = 1  # Users can add multiple courts inline


class CourtRequestInline(admin.StackedInline):
    model = CourtRequest
    extra = 1  # Allows users to input number of courts dynamically

    def save_model(self, request, obj, form, change):
        """
        Override save to create courts dynamically and remove the CourtRequest entry.
        """
        obj.save()
        existing_courts = Court.objects.filter(venue=obj.venue, sport=obj.sport).count()
        for i in range(1, obj.court_count + 1):
            Court.objects.create(
                venue=obj.venue,
                sport=obj.sport,
                court_number=existing_courts + i,  # Assign unique court numbers
                price=obj.price,
            )
        obj.delete()  # Remove CourtRequest after processing




    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(owner__user=request.user)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "owner":
            try:
                venue_owner = VenueOwnerProfile.objects.get(user=request.user)
                kwargs["initial"] = venue_owner.id
                kwargs["queryset"] = VenueOwnerProfile.objects.filter(user=request.user)
            except VenueOwnerProfile.DoesNotExist:
                kwargs["queryset"] = VenueOwnerProfile.objects.none()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)



    

class VenueAdmin(admin.ModelAdmin):
    list_display = ['name', 'address']
    inlines = [VenueImageInline,CourtRequestInline]

    # def get_queryset(self, request):
    #     qs = super().get_queryset(request)
    #     if request.user.is_superuser:
    #         return qs
    #     return qs.filter(owner__user=request.user)

    # def formfield_for_foreignkey(self, db_field, request, **kwargs):
    #     if db_field.name == "owner":
    #         try:
    #             venue_owner = VenueOwnerProfile.objects.get(user=request.user)
    #             kwargs["initial"] = venue_owner.id
    #             kwargs["queryset"] = VenueOwnerProfile.objects.filter(user=request.user)
    #         except VenueOwnerProfile.DoesNotExist:
    #             kwargs["queryset"] = VenueOwnerProfile.objects.none()
    #     return super().formfield_for_foreignkey(db_field, request, **kwargs)

    
# Registering models
admin.site.register(CustomerProfile)
admin.site.register(Venue, VenueAdmin)
admin.site.register(VenueImage)
admin.site.register(Court)
admin.site.register(Sporttype)
admin.site.register(Banner)
admin.site.register(Rating)
admin.site.register(Booking)

class VenueOwnerProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone', 'is_approved', 'created_at')
    list_filter = ('is_approved', 'created_at')  
    search_fields = ('user__username', 'user__email', 'phone')  
    actions = ['approve_venue_owners']

    def approve_venue_owners(self, request, queryset):
        for profile in queryset:
            profile.approve()
        self.message_user(request, "Selected venue owners have been approved and granted staff privileges.")
    
    approve_venue_owners.short_description = "Approve selected venue owners"

admin.site.register(VenueOwnerProfile, VenueOwnerProfileAdmin)


