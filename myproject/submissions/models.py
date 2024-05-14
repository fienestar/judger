from django.db import models

class Submission(models.Model):
    code = models.TextField()
    language = models.CharField(max_length=100)
    # created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.language