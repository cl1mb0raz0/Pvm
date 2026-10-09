from django.urls import path

from . import views

app_name = "backups"

urlpatterns = [
    path("", views.backup_list, name="list"),
    path("new/", views.backup_create, name="create"),
    path("new-full/", views.backup_create_full, name="create_full"),
    path("reset/", views.reset, name="reset"),
    path("delete-all/", views.delete_all, name="delete_all"),
    path("factory-reset/", views.factory_reset, name="factory_reset"),
    path("<int:pk>/rename/", views.backup_rename, name="rename"),
    path("<int:pk>/restore/", views.backup_restore, name="restore"),
    path("<int:pk>/delete/", views.backup_delete, name="delete"),
    path("<int:pk>/download/", views.backup_download, name="download"),
]
