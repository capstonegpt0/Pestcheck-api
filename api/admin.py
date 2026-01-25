from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, PestDetection, PestInfo, InfestationReport


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['username', 'email', 'first_name', 'last_name', 'phone', 'created_at']
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'created_at']
    search_fields = ['username', 'email', 'first_name', 'last_name', 'phone']
    ordering = ['-created_at']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {'fields': ('phone', 'created_at')}),
    )
    readonly_fields = ['created_at']

admin.site.register(User)
admin.site.register(PestDetection)
admin.site.register(PestInfo)
admin.site.register(InfestationReport)
admin.site.register(Farm)

@admin.register(PestDetection)
class PestDetectionAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'pest_name', 'crop_type', 'severity', 'confidence', 'detected_at']
    list_filter = ['crop_type', 'severity', 'detected_at']
    search_fields = ['pest_name', 'user__username', 'address']
    readonly_fields = ['detected_at']
    ordering = ['-detected_at']
    
    fieldsets = (
        ('Detection Info', {
            'fields': ('user', 'image', 'pest_name', 'crop_type')
        }),
        ('Results', {
            'fields': ('confidence', 'severity')
        }),
        ('Location', {
            'fields': ('latitude', 'longitude', 'address')
        }),
        ('Metadata', {
            'fields': ('detected_at',)
        }),
    )


@admin.register(PestInfo)
class PestInfoAdmin(admin.ModelAdmin):
    list_display = ['name', 'scientific_name', 'crop_affected']
    list_filter = ['crop_affected']
    search_fields = ['name', 'scientific_name', 'crop_affected']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'scientific_name', 'crop_affected', 'image_url')
        }),
        ('Description', {
            'fields': ('description', 'symptoms')
        }),
        ('Management', {
            'fields': ('control_methods', 'prevention')
        }),
    )


@admin.register(InfestationReport)
class InfestationReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'detection', 'area_affected', 'is_verified', 'reported_at']
    list_filter = ['is_verified', 'reported_at']
    search_fields = ['detection__pest_name', 'notes']
    readonly_fields = ['reported_at']
    ordering = ['-reported_at']
    
    fieldsets = (
        ('Report Info', {
            'fields': ('detection', 'area_affected', 'notes')
        }),
        ('Status', {
            'fields': ('is_verified', 'reported_at')
        }),
    )