# Generated by Django 4.2 on 2023-04-19 14:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('code10', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userstatus',
            name='lastLogin',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
