from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from rest_framework import status
from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from .models import IPRegisterAttempt
MAX_ATTEMPTS = 3
COOLDOWN = timedelta(minutes=60)
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
@api_view(["POST"])
def login(request):
    try:
        # if request.user.is_authenticated:
        #     return JsonResponse({"data":{"message":"login successfully","status":"ok"},"message":"success"},status=status.HTTP_200_OK)
        # if not "attempt" in request.session:
        #     request.session["attempt"] = 0
        # if request.session["attempt"] >= 3:
        #     return JsonResponse({"data":{"message":"maxiume number try agine later","status":"ok"},"message":"error"},status=status.HTTP_400_BAD_REQUEST)
        username = request.data["username"]
        password =request.data["password"]
        user = authenticate(request=request,username=username,password=password)

        if user is not None:
            token = RefreshToken.for_user(user)
            # request.session["attempt"] = 0
            return JsonResponse({"data":{"message":"successfully login","data":{"username":username,"access":str(token.access_token),"refresh":str(token),"id":user.id},"status":"ok"},"message":"successfully"},status=status.HTTP_200_OK)

        else:
            # request.session["attempt"] +=1
            return JsonResponse({"data":{"message":"username or password not found","status":"ok"},"message":"errror"},status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:

        return JsonResponse(
            {"data": {"message": "IP Band ", "status": "ok"}, "message": "errror"},
            status=status.HTTP_400_BAD_REQUEST)
@api_view(["POST"])
def register(request):
    ip = get_client_ip(request)
    obj, created = IPRegisterAttempt.objects.get_or_create(ip=ip)
    try:
        # if not "attempt" in request.session:
        #     request.session["attempt"] = 0
        # if request.session["attempt"] >= 3:
        #     return JsonResponse(
        #         {"data": {"message": "maxiume number try agine later", "status": "ok"}, "message": "error"},
        #         status=status.HTTP_400_BAD_REQUEST)


        username = request.data["username"]
        password = request.data["password"]
        email = request.data["email"]
        password2 = request.data["password2"]
        full_name = request.data["full_name"]
        # ip = get_client_ip(request)
        # obj, created = IPRegisterAttempt.objects.get_or_create(ip=ip)


        if obj.attempts >= MAX_ATTEMPTS and timezone.now() - obj.last_attempt < COOLDOWN:
            return JsonResponse({
                "data": {"message": f"Your IP  is temporarily blocked from registering", "status": "error"},
                "message": "error"
            }, status=403)
        try:
            validate_email(email)
        except ValidationError:
            obj.attempts += 1
            obj.last_attempt = timezone.now()
            obj.save()
            return JsonResponse({"data": {"message": "please enter valid email", "status": "ok"}, "message": "error"},
                        status=status.HTTP_400_BAD_REQUEST)
        if password != password2:
            obj.attempts += 1
            obj.last_attempt = timezone.now()
            obj.save()
            return JsonResponse({"data": {"message": "password not match", "status": "ok"}, "message": "error"},
                        status=status.HTTP_400_BAD_REQUEST)


        elif User.objects.filter(email=email).exists():
            obj.attempts += 1
            obj.last_attempt = timezone.now()
            obj.save()
            return JsonResponse({"data": {"message": "email is alerdy exiests", "status": "ok"}, "message": "error"},
                                status=status.HTTP_400_BAD_REQUEST)
        elif User.objects.filter(username=username).exists():
            obj.attempts += 1
            obj.last_attempt = timezone.now()
            obj.save()
            return JsonResponse({"data": {"message": "username is alerdy exiests", "status": "ok"}, "message": "error"},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            user = User.objects.create_user(username=username,email=email,password=password)
            # # user.save()
            # request.session["attempt"] = 0
            return JsonResponse({"data": {"message": "successfully created accounts", "status": "ok"}, "message": "success"},
                        status=status.HTTP_201_CREATED)
    except:
        obj.attempts += 1
        obj.last_attempt = timezone.now()
        obj.save()
        return JsonResponse({"data": {"message": "bad request", "status": "ok"}, "message": "error"},
                            status=status.HTTP_400_BAD_REQUEST)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        token = request.data["refresh"]
        tokenm = RefreshToken(token)
        tokenm.blacklist()
        return JsonResponse({"data":{"message":"successfully logout","status":"ok"},"message":"success"},status=status.HTTP_200_OK)
    except:
        return JsonResponse({"data":{"message":"tokens not found","status":"ok"},"message":"error"},status=status.HTTP_400_BAD_REQUEST)

