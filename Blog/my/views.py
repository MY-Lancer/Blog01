from django.shortcuts import render

# Create your views here.

#默认页
def index(request):
    return render(request,'index.html')
