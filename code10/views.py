from django.shortcuts import render
from django.http import HttpResponse

from django.contrib import messages
from .models import User



# Create your views here.

async def home(request):
    z=calculate(request)
    
    return HttpResponse('Hello World')

#?page loading does not work with async await
def home2(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = User(name=name, email=email, password=password)
        user.save()
        # messages.success(request, 'User created successfully')  works in html file
    
    return render(request, 'hello.html', {'name': 'hh'})

def calculate(request):
    x =  1
    y =  2
    z = int(x) + int(y)
    return z
