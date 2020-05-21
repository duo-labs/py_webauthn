from django.contrib import admin
from django.contrib.auth.models import User, Group
from django_webauthn.models import WA_User
from django.db.models import ManyToOneRel, ForeignKey, OneToOneField


MySpecialAdmin = lambda model: type('SubClass'+model.__name__, (admin.ModelAdmin,), {
    'list_display': [x.name for x in model._meta.fields],
    'list_select_related': [x.name for x in model._meta.fields if isinstance(x, (ManyToOneRel, ForeignKey, OneToOneField,))]
})

admin.site.unregister(User)
admin.site.unregister(Group)
# admin.site.unregister(WA_User)
admin.site.register(User, MySpecialAdmin(User))
admin.site.register(Group, MySpecialAdmin(Group))
admin.site.register(WA_User, MySpecialAdmin(WA_User))
