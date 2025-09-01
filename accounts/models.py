from django.db import models
from django.utils import timezone
from datetime import timedelta

class IPRegisterAttempt(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    attempts = models.IntegerField(default=0)
    last_attempt = models.DateTimeField(auto_now=True)
