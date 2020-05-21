from django.contrib.auth.models import User
from django.db import models


class WA_User(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, null=False, on_delete=models.DO_NOTHING)
    ukey = models.CharField(max_length=128, unique=True, null=False)
    credential_id = models.CharField(max_length=250, unique=True, null=False)
    display_name = models.CharField(max_length=160, unique=False, null=False)
    pub_key = models.CharField(max_length=256, unique=True, null=True)
    # run counter to prevent replay attacks
    sign_count = models.IntegerField(default=0)
    username = models.CharField(max_length=80, unique=True, null=False)
    # relying party url
    rp_id = models.CharField(max_length=253, null=False)
    # url of web site that use is loggin into
    icon_url = models.CharField(max_length=2083, null=False)

    def __unicode__(self):
        return '<User %r %r>' % (self.display_name, self.username)
