"""Blog URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include,re_path
from users.views import *
urlpatterns = [
    
    #注册页面
    path('register/',RegisterView.as_view(),name='register'),
    
    #图片验证码
    path('imagecode/',ImageCodeView.as_view(),name='imagecode'),
    
    #短信发送
    path('smscode/',SmsCodeView.as_view(),name='smscode'),
    
    #登录界面
    path('login/',LoginView.as_view(),name='login'),

    #退出登录
    path('logout/',LogoutView.as_view(),name='logout'),

    #忘记密码
    path('forgetpassword/', ForgetPasswordView.as_view(),name='forgetpassword'),

    #用户中心展示
    path('center/', UserCenterView.as_view(),name='center'),

    #添加用户写博客的路由
    path('writeblog/', WriteBlogView.as_view(),name='writeblog'),


]

