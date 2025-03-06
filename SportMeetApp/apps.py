from django.apps import AppConfig

class SportMeetAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'SportMeetApp'

    def ready(self):
        import SportMeetApp.signals
       
