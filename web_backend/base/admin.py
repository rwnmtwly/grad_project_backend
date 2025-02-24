from .models import User
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

#custom UserAdmin class
class CustomUserAdmin(UserAdmin):
    # Fields to display in the list view of the admin panel
    list_display = ('email', 'username', 'is_staff', 'is_active', 'created_at')

    # Fields to enable search functionality
    search_fields = ('email', 'username')

    # Fields to enable filtering
    list_filter = ('is_staff', 'is_active', 'created_at')

    # Fieldsets for the add/edit user page
    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'is_superuser')}),
        ('Important Dates', {'fields': ('last_login',)}),
    )

    # Fields to use when adding a new user in the admin panel
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'is_staff', 'is_active'),
        }),
    )


# Register your models here.

admin.site.register(User, CustomUserAdmin)