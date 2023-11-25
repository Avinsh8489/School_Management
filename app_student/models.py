from django.db import models
from app_admin.models import User, Subject
# Create your models here.


class Standard(models.Model):
    std_code = models.CharField(max_length=50, unique=True)
    std_name = models.CharField(max_length=100)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.std_code}-{self.std_name}"


# Student
class student(models.Model):
    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    country_code = models.CharField(max_length=6)
    phone = models.CharField(max_length=20, unique=True)
    email = models.EmailField(max_length=254, unique=True)
    date_of_bith = models.DateField(auto_now=False, auto_now_add=False)
    date_of_adminssion = models.DateField(auto_now=False, auto_now_add=False)
    date_of_leaving = models.DateField(auto_now=False, auto_now_add=False)

    gender = models.CharField(max_length=10, choices=[(
        "Male", "Male"), ("Female", "Female"), ("Other", "Other")], default="Male")

    standard_id = models.ForeignKey(Standard, on_delete=models.CASCADE,
                                    related_name='StdTech',
                                    related_query_name='StdTechs',
                                    limit_choices_to={'is_active': True})

    teacher_id = models.ForeignKey(User, on_delete=models.CASCADE,
                                   related_name='StuTech',
                                   related_query_name='StuTechs',
                                   limit_choices_to={'is_active': True})

    stu_main_subject_id = models.ForeignKey(Subject, on_delete=models.CASCADE,
                                            related_name='studentMainSub',
                                            related_query_name='studentMainSubs',
                                            limit_choices_to={
                                                'is_active': True},
                                            null=True, blank=True)

    stu_subjects_ids = models.ManyToManyField(Subject)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name}-{self.last_name}"


class CLB_Review(models.Model):
    Review_Answer = [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (5, 5)
    ]

    review_answer = models.IntegerField(choices=Review_Answer, default=0)
    comment = models.TextField(max_length=1000, null=True, blank=True)

    Review_of = models.ForeignKey(student, on_delete=models.CASCADE,
                                  related_query_name='ReviewUserID',
                                  limit_choices_to={
                                      'is_active': True, },
                                  null=True, blank=True)

    created_on = models.DateTimeField(auto_now_add=True)
