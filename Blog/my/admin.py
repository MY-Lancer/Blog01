from django.contrib import admin

# Register your models here.

#注册模型类
from my.models import * 

#注册文章标签类
admin.site.register(ArticleCategory)

#注册文章类
admin.site.register(Article)

#注册评论类
admin.site.register(Comment)
