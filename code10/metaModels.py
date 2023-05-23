from django.db import models
from django_extensions.db.models import TimeStampedModel
from django.utils import timezone


class SoftDeleteModel(TimeStampedModel):

    is_deleted = models.BooleanField(default=False)

    def soft_delete(self):
        self.is_deleted = True
        self.save()

    def restore(self):
        self.is_deleted = False
        self.save()

    class Meta:
        abstract = True