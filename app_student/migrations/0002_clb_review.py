# Generated by Django 4.2.7 on 2023-11-25 11:04

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app_student', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CLB_Review',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('review_answer', models.IntegerField(choices=[(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5)], default=0)),
                ('comment', models.TextField(blank=True, max_length=1000, null=True)),
                ('created_on', models.DateTimeField(auto_now_add=True)),
                ('Review_of', models.ForeignKey(blank=True, limit_choices_to={'is_active': True}, null=True, on_delete=django.db.models.deletion.CASCADE, related_query_name='ReviewUserID', to='app_student.student')),
            ],
        ),
    ]