# Standard library imports
import pdb
import json
import redis
from random import randint
import traceback
# Python logging package
import logging
ielite_logger = logging.getLogger('ielite')
ielite_except_logger = logging.getLogger('ielite_except')

# Related third party imports
import hashlib
from django.conf import settings
from django.core.mail import send_mail
# Django packages import
from django.shortcuts import render, render_to_response, redirect
from django.template import RequestContext
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User, Group, Permission
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.utils import translation
from django.utils.decorators import method_decorator
from django.contrib.contenttypes.models import ContentType
# Local Django application imports
from .models import *
from college_management.models import UniversityDetails
from django.views.generic.base import View, TemplateView
import urllib
import pytz
from django.http import HttpResponseRedirect
# from programme_management.models import *
# from termsandconditions.decorators import terms_required
from django.core import serializers
from oauth2_provider.views import TokenView
from django.contrib import messages
from rest_framework.views import APIView
from pyfcm import FCMNotification
from rest_framework.response import Response
import datetime
from notifications.signals import notify
from .config import FCM_API_KEY
from django.contrib.auth import logout
from django.contrib.auth.views import * 
from user_management.task import send_activation_mail
from .methods import *
from .forms import UserRoleMapChoicesFieldForm
from .get_build_no import get_build_number
from .methods import accept_termsandconditions
from ielite import content
from auditlog.models import *
from online_exam.models import ExamSeries as NewExamSeries,Departments,AcademySession
from online_exam.models import ExamSeries
from dvs.models import EvaluatorToExamgroup
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, EmailMessage, BadHeaderError
from django.core.mail import EmailMessage
from .token_generator import account_activation_token
import shutil
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from datetime import datetime
import numpy as np
from user_management.api_views import ErrorMessage
from cryptography.fernet import Fernet
from mirage.crypto import Crypto
#from eventlog.events import EventGroup
#e = EventGroup()

################ Methods for Device ############

def get_user_details_by_role(role,edc):
    response_dict = {}
    response_list = []
    try:
        coll_obj = CollegeDetails.objects.filter(edc = edc)
        role_id = RoleManager.objects.get(name = role).pk
        user_obj = UserDetails.objects.filter(object_id__in = coll_obj.values_list("pk"),roles = role_id)
        for each in user_obj:
            response_dict = {}
            response_dict.update({"username":each.user.username,"device_id":each.device_user_id,"passcode":each.passcode})
            response_list.append(response_dict)
        # pdb.set_trace()
    except:
        pass
    return response_list
################ Methods for Device ############

def index(request):
    context = {}
    # country_data = list(country.objects.all().values_list('name',flat=True))
    # context = {'country_data': country_data}
    # pdb.set_trace()
    # lang = 'zh-hans'
    # translation.activate(lang)
    # request.LANGUAGE_CODE = lang
    # flag = False
    flag = not RoleManager.objects.filter(name = "TSDADMIN").exists()
    # if len(role_obj) < 1:
    #     flag = True
    context.update({"flag":flag})
    try:
        if request.user.is_authenticated():
            ielite_logger.info('User Authenticated')
            return redirect('/dashboard')
        ielite_logger.info('Wrong Credentials')
        context.update({'status':True,})
        if 'allauth.socialaccount.providers.giis_auth' in settings.INSTALLED_APPS:
            context.update({"GIIS_LOGIN":True})
        return render(request, 'index.html', context)
    except Exception as e:
        ielite_except_logger.critical('user_management \t index \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return render(request, 'index.html', context)

def check_uniqueness(request):
    try:
        # pdb.set_trace()
        response_dict = {}
        par1 = eval(request.POST.get("par1"))
        par2 = request.POST.get("par2")
        value = request.POST.get("value")
        kwargs = {'{0}'.format(par2): value}
        flag = par1.objects.filter(**kwargs).exists()
        response_dict.update({"flag": flag})
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript',
                            status=200)
    except Exception as e:
        ielite_except_logger.critical('user_management \t add_details \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript',
                            status=500)

def add_details(request):
    try:
        # import ipdb;ipdb.set_trace()
        response_dict = {}
        university_name = request.POST.get("un_id")
        university_short_name = request.POST.get("un_short_id")
        user_id = request.POST.get("user_id","tsdadmin")
        email = request.POST.get("email")
        user_password = request.POST.get("user_password")
        logo = request.FILES['un_logo_id']
        fs = FileSystemStorage()
        filename = fs.save('university/logo/'+logo.name, logo)
        uploaded_file_url = fs.url(filename)
        u_obj = UniversityDetails(
            university_name = university_name,
            university_short_name = university_short_name,
            created_by = 1,
            logo = uploaded_file_url,
            )
        u_obj.save()
        user_obj = user = User.objects.create_user(user_id,email,user_password)
        user_obj.save()
        try:
            rm_obj = RoleManager.objects.get(name = "TSDADMIN")
        except:
            rm_obj = RoleManager(
                content_type = ContentType.objects.get(app_label='college_management',model = "universitydetails"),
                name = "TSDADMIN",
                created_by = 1,
            )
            rm_obj.save()

        perm_obj = Permission.objects.all()
        for each in perm_obj:
            rm_obj.permissions.add(each)
        user.groups.add(rm_obj)
        usd = UserDetails(
            title=1,
            first_name="TSD", 
            last_name = "ADMIN",
            address1 = "-",
            address2 = "-",
            phone_no = "-",
            fax_no = "-",
            user = user,
            email_id = email,
            gender = 2,
            qualification = "-",
            designation = "-",
            experience = 1,
            specialization = "-",
            description = "-",
            photo = "",
            signature = "",
            object_id = 1,
            created_by = 1,
            dob = pytz.utc.localize(datetime.datetime.now()),
            device_user_id = 999999,
            passcode = 0,
            )
        usd.save()
        UserRoleMap(
            status=True, 
            user_details_id=usd, 
            role_manager_id=rm_obj, 
            # end_time = pytz.utc.localize(datetime.datetime.now()),
            # start_time = pytz.utc.localize(datetime.datetime.now()),
            priority_role=True,
            object_id = 1,
            is_active = True,
            permanent_role = True,
            created_by = 1,
            ).save()
        password_reset(request,html_email_template_name='registration/password_reset_email.html',from_email = settings.EMAIL_HOST_USER)
        ielite_logger.info("user_management \t add_details \t add user details")
        ielite_logger.debug("user_management \t add_details \t add user details")
        return HttpResponse(json.dumps(response_dict),
                                content_type='application/javascript',
                                status=200)
    except Exception as e:
        ielite_except_logger.critical('user_management \t add_details \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript',
                            status=500)



def login_resetpassword(request):

    post_data = request.POST
    username = post_data.get('username')
    try:
        obj_user = User.objects.get(username=username)
        obj_user.is_active=False
        obj_user.save()
        messages = "User is deactivated contact admin"
        response_dict = {"status": True, "messages":messages}
        ielite_logger.info("user_management \t login_resetpassword \t check user is registred or not ")
        ielite_logger.debug("user_management \t login_resetpassword \t check user is registred or not ")
        return HttpResponse(json.dumps(response_dict),content_type='application/javascript')
    except:
        messages = "User is doesnot Exists"
        response_dict = {"status": True, "messages":messages}
        ielite_logger.info("user_management \t login_resetpassword \t check user is registred or not ")
        ielite_logger.debug("user_management \t login_resetpassword \t check user is registred or not ")
        return HttpResponse(json.dumps(response_dict),content_type='application/javascript')



def delete_user_session_request(request):

    username = request.POST.get("username")
    obj = UserSession.objects.get(user=User.objects.get(username=username))
    try:
        delete_user_sessions(obj)
    except:
        pass
    response_dict = {"status": True, "messages": "User Sucessfully delete session"}
    return HttpResponse(json.dumps(response_dict),content_type='application/javascript')


from django.views.decorators.csrf import csrf_exempt, csrf_protect


@csrf_exempt
def login_call(request):
    response_dict = {"code":500}
    c = Crypto()
    #import ipdb; ipdb.set_trace()
    try:
        try:
            body_decoded = request.body.decode('utf-8')
            body_json = json.loads(body_decoded)
            for key, value in body_json.items():
                if not request.POST._mutable:
                    request.POST._mutable = True
                request.POST[key] = value
            if request.POST._mutable:
                request.POST._mutable = False
        except:
            pass
        post_data = request.POST
        client_secret=post_data.get('client_secret')
        client_id= post_data.get('client_id')
        grant_type = post_data.get('grant_type')
        device_name=post_data.get('device_name')
        username = post_data.get('username')
        password = post_data.get('password')
        
        
        if grant_type == 'password':
            
            token_obj = TokenView()
            obj = token_obj.post(request)
            obj1 = obj.content
            obj1 = obj1.decode('utf-8')
            obj1 = json.loads(obj1)
            if obj1.get('error_description'):
                res = obj1
            else:
                res = obj1
        try:
            MobileTokenFlavour.objects.create(created_by=User.objects.get(username=request.POST.get('username')).pk,token=obj1['access_token'],flavour=device_name,user=request.POST['username'])
        except:
            pass

        if device_name =='A' or device_name =='I':
            # import ipdb;ipdb.set_trace()
            if obj1.get('error_description'):
                res={"status":False,"message":"Invalid Credentials","data":{}}
            else:
                res={"status":True,"data":obj1}
            return JsonResponse(res)

        chk_isactive = User.objects.filter(username=username,is_active = False)
        if chk_isactive:
            response_dict = {"status": False, "messages": "User is not Active", "code": 420}
            return HttpResponse(json.dumps(response_dict))
        
        last_login_flag = False
        # ielite_logger.debug(
            # "%s is username %s is his password." % (username, password))
        user = authenticate(
            username=username,
            password=password)
        # flag to determine whether login is from IE or different source as GIIS

        request.session.update({'IE_LOGIN':True})
        if user_check_data(user):
            response_dict = {"status": False, "messages": "User Session Exists Other System" ,"code":300}
            return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript')
        elif user is not None:
            
            user_obj = User.objects.get(username=username,)
            if user_obj.groups.all()[0]=='STUDENT':
                last_login = user_obj.last_login
                if not last_login or (last_login and not LogEntry.objects.filter(content_type_id = ContentType.objects.filter(app_label = "auth",\
                                                                                model = "user"),object_id = request.user.pk,action = 1, \
                                                                                changes__contains='password').exists()):
                    user_obj.last_login = None
                    user_obj.save()
                    last_login_flag = True
            

            login(request, user)
            if request.user.groups.all().exists():
                ielite_logger.debug(login)


                role=UserRoleMap.objects.filter(user_details_id__user__username=username).values('role_manager_id__name')[0].get('role_manager_id__name')
                last_time=user_obj.last_login
                if(post_data.get('token',None)):
                    response_dict = {"last_login_flag":last_login_flag,"status": "login sucess!",
                                     "url": "/authoring/qp", "code":200,"last_login_time":last_time.strftime("%d-%b-%Y (%H:%M:%S)")}
                else:
                    user =  c.decrypt(UserDetails.objects.filter(user =user_obj)[0].first_name)
                    if user:
                        pass
                    else:
                        user = username
                    response_dict = {"last_login_flag":last_login_flag,'token':res,'user_name':user,'user_id':request.user.id,"status": "login sucess!","role":role,
                                 "url": "/dashboard", "code":200,"last_login_time":last_time.strftime("%d-%b-%Y (%H:%M:%S)")}
            else:
                ielite_logger.info('user_management \t login_call \t Login attempt failed.!')
                logout(request)
                response_dict = {"status": "login failed!", "url": "/", "code":500}
        else:
            ielite_logger.info("Login attempt failed.!")
            response_dict = {"status": "login failed!", "url": "/", "code":400}
        # accept_termsandconditions(user = request.user,ip_address = request.META['REMOTE_ADDR'],terms = "mindlogicx1")
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript')
    except Exception as e:
        ielite_except_logger.critical('user_management \t login_call \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript',
                            status=500)



@csrf_exempt
def RefreshToken(request):
    try:
        try:
            body_decoded = request.body.decode('utf-8')
            body_json = json.loads(body_decoded)
            for key, value in body_json.items():
                if not request.POST._mutable:
                    request.POST._mutable = True
                request.POST[key] = value
            if request.POST._mutable:
                request.POST._mutable = False
        except:
            pass
        post_data = request.POST
        client_secret=post_data.get('client_secret')
        client_id= post_data.get('client_id')
        grant_type = post_data.get('grant_type')
        device_name=post_data.get('device_name')
        username = post_data.get('username')
        password = post_data.get('password')

        if grant_type == 'refresh_token':
            token_obj = TokenView()
            obj = token_obj.post(request)
            obj1 = obj.content
            obj1 = obj1.decode('utf-8')
            obj1 = json.loads(obj1)
            if obj1.get('error_description'):
                res = {"status": False,
                       "data" : obj1,
                       "message" : "The user ID/Password is invalid. Please enter valid user ID/Password."
                       }
            elif obj1.get('error') == 'invalid_grant':
                res = {"status": False,
                       "data" : obj1,
                       "message" : "Invalid details"
                       }
            else:
                res={"status":True,"data":obj1}
            return JsonResponse(res)
    except Exception as e:
        res={"status":False,"data":''}
        return JsonResponse(res)


from django.views.decorators.cache import cache_page

@login_required(login_url="/")
#@terms_required
#@cache_page(60 * 5)
def dashboard(request):
    ielite_logger.info('Directed to dasboard on sucessfull validation of user')
    context = {}
    try:
        ################ added by naveen ## this query for to check the reset_password flag ############
        # import ipdb;ipdb.set_trace()
        # obj = UserDetails.objects.get(user=request.user)
        # if obj.reset_password == False:
        #     return render(request,'new_include/create_pwd.html',locals())
        # return render(request,'dashboard.html')
            
        ####### naveen code ends here ##############

        # pdb.set_trace()
        #############################
        # this code is check, if the login is from giis oauth
        if 'allauth.socialaccount.providers.giis_auth' in settings.INSTALLED_APPS and not request.session.get('IE_LOGIN',False):
            role_creation = user_role_creation(request)
            if not role_creation:
                raise ("returned false response from user_role_creation")
            # add condition to check the ios or android in request object and return API json response
        #############################
        role_id = request.user.groups.get().id
        ct_obj = RoleManager.objects.get(group_ptr__pk = role_id).content_type
        menu_list = LevelMaster.objects.get(levels_master = ct_obj).level_config_map.all()
        context.update({"menu_list":menu_list,})
        ielite_logger.info("user_management \t dashboard \t Directed to dasboard on sucessfull validation of user")
        ielite_logger.debug("user_management \t dashboard \t Directed to dasboard on sucessfull validation of user ")
    except Exception as e:
        ielite_except_logger.critical('user_management \t dashboard \t '+str(e) +'\n'+ str(traceback.format_exc()))
    return render(request,'dashboard.html',context=context)


##### added by naveen ##### this function is for to create new password for first login user and change status flag of reset_password field ###############
from django.views.decorators.csrf import ensure_csrf_cookie
@csrf_exempt
@ensure_csrf_cookie

def create_pwd(request):

    if request.method == 'POST':
        # import ipdb;ipdb.set_trace()
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            user_obj = User.objects.get(pk=request.user.pk)
            user_obj.set_password(password)
            user_obj.save()
            user_detail = UserDetails.objects.filter(user=request.user)
            user_detail.update(reset_password = True)
            return HttpResponseRedirect('/')
        return HttpResponseRedirect('/')
    else:
       return HttpResponseRedirect('/')

class CreatePassword(ErrorMessage,APIView):
    def post(self,request):
        response_dict = {"status":True,"message":"data saved","data":{}}
        try:
            password = request.data.get('password')
            confirm_password = request.data.get('confirm_password')
            # old_password =  request.data.get('old_password')
            user_pks = request.data.get('user_pk')
            # password_instance = StudentTmpPwd.objects.get(code=old_password)
            # password_obj = User.objects.filter(pk=user_pks,password=old_password)
            password_obj = request.user.check_password(request.data.get("old_password"))

            if password_obj:

                if password == confirm_password:
                    user_obj = User.objects.get(pk=request.user.pk)
                    # u = User.objects.get(pk = request.user.pk)
                    user_obj.set_password(password)
                    user_obj.save()
                    user_detail = StudentTmpPwd.objects.filter(student_temp_pwd=user_pks)
                    user_detail.update(code = password)
                    return Response(response_dict)
                return Response({"status":False,"msg":'password does not match'})
            else:
                return Response({"status":False,"msg":'old password does not exist'})

        except Exception as e:
            # response_dict['status'] = False
            response_dict['message'] = 'data not found'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response({"status":False,"msg":'password does not match'})

############### naveen code ends here ########################

def pop_loc():
    try:
        with open('loc.json') as data_file:
            data = json.load(data_file)
        country_data = country.objects.get(name='India')
        ielite_logger.info('Country object obtained')
        for each in data['data'].keys():
            if (data['data'][each]['country_name'] == 'India'):
                state_data = state(name=data['data'][each]['state_name'],
                                   country=country_data,
                                   )
                try:
                    state_data.save()
                except:
                    state_data = state.objects.get(
                        name=data['data'][each]['state_name'])

                city_data = city(name=data['data'][each]['city_name'],
                                 state=state_data,
                                 )
                try:
                    city_data.save()
                except:
                    pass
    except Exception as e:
        ielite_except_logger.critical('user_management \t pop_loc \t '+str(e) +'\n'+ str(traceback.format_exc()))
 

def save_user_info(request):
    response_dict = {}
    try:
        if request.method == 'POST':
            post_data = request.POST
            title = post_data.get('title')
            gender = post_data.get('gender')
            author_name = post_data.get('author_name')
            mobile_number = post_data.get('mobile_number')
            email = post_data.get('email')
            country_data = post_data.get('country')
            state_data = post_data.get('state')
            city_data = post_data.get('city')
            address = post_data.get('address')
            #password = request.POST['password']
            user_object = User.objects.create_user(password=author_name,
                                                   username=author_name)
            user_object.save()
            ielite_logger.info('User created in Djnago USER table')
            save_data = Author_Registration(
                user=user_object,
                Author_name=author_name,
                emailid=email,
                mobilenumber=mobile_number,
                password=author_name,
                Gender=gender,
                Residentail_Address=address,
                country=country.objects.get(name=country_data),
                state=state.objects.get(name=state_data),
                city=city.objects.get(name=city_data),
            )
            save_data.save()
            response_dict = {"data": 'You are registered sucessfully!'}
            ielite_logger.info('User created in Author_registration')
            return HttpResponse(json.dumps(response_dict),
                                content_type='application/javascript')
        else:
            ielite_logger.info('Data not saved')
            return HttpResponse(json.dumps(response_dict),
                                content_type='application/javascript', status=403)
    except Exception as e:
        ielite_except_logger.critical('user_management \t save_user_info \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript', status=500)


def get_state_data(request):
    '''function to get state info'''
    response_dict = {}
    try:
        r = redis.StrictRedis(host='localhost', port=6379, db=0)
        ielite_logger.info('Connected to REDIS server')
        if (r.get('state_val')):
            city_list = []
            state_list = (eval(r.get("state_val"))).keys()
            city_list = eval(r.get("state_val"))
            ielite_logger.info('STATE and CITY values are obtained.')
            response_dict = {"state_data": state_list,
                             'city_data': city_list}
        else:
            value_dict = {}
            state_obj = state.objects.filter(country=country.objects.get
                                             (name=str(request.POST['country'])))
            state_list = map(lambda val: str(val),
                             list(state_obj.values_list('name',
                                                        flat=True)))

            ielite_logger.debug(
                "%s is State_obj %s is  state_list." % (state_obj, state_list))
            for each in state_list:
                city_list = map(lambda val: str(val),
                                list(city.objects.filter(state=state.objects.get(name=each))
                                     .values_list('name',
                                                  flat=True)))
                value_dict.update({each: city_list})
            r.set("state_val", value_dict)
            response_dict = {"state_data": state_list,
                             'city_data': city_list}
            ielite_logger.info('STATE and CITY values are obtained.')
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript')
    except Exception as e:
        ielite_except_logger.critical('user_management \t get_state_data \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript', status=500)


def get_roles(request):
    context = {}
    try:
        user = User.objects.all()
        group = Group.objects.all()
        context.update({'users': user,
                        'group': group})
        ielite_logger.info('Obtained all USERS & GROUPS.')
        return render(request,
                      'roles-and-privileges.html',
                      context)
    except Exception as e:
        ielite_except_logger.critical('user_management \t get_roles \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return render(request,
                      'roles-and-privileges.html',
                      context)


def add_new_group(request):
    response_dict = {}
    try:
        post_data = request.POST
        group = post_data.get('role')
        Group.objects.get_or_create(name=group)
        ielite_logger.info('user_management \t add_new_group \t Added new group if doesnot exist')
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript')
    except Exception as e:
        ielite_except_logger.critical('user_management \t add_new_group \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript', status=500)


def add_new_group_permission(request):
    response_dict = {}
    try:
        post_data = request.POST
        group = post_data.get('role')
        user = post_data.get('user')
        per_obj = post_data.get('per_obj')
        per_obj = json.loads(per_obj)
        ielite_logger.debug(group, user, per_obj)(
            "%s is group,%s is  user,%s is  per_obj." % (group, user, per_obj))
        try:
            user_data = User.objects.get(username=user)
            ielite_logger.info('Obtained user_data object')
        except:
            user_data = ''

        group_data = Group.objects.get(name=group)
        per_obj = filter(lambda x: per_obj[x], per_obj)
        for each in per_obj:
            permission = Permission.objects.get(codename=each)
            group_data.permissions.add(permission)
            if user_data:
                user_data.groups.add(group_data)
        ielite_logger.info('user_management \t add_new_group_permission \t Added user groups ')
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript')
    except Exception as e:
        ielite_except_logger.critical('user_management \t add_new_group_permission \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript', status=500)


def get_group_permission(request):
    response_dict = {}
    try:
        post_data = request.POST
        group = post_data.get('role')
        group_data = Group.objects.get(name=group)
        ielite_logger.info('Obtained GROUPS object')
        permission_list = list(group_data.permissions.all().
                               values_list('codename',
                                           flat=True))
        ielite_logger.info('user_management \t get_group_permission \t get the permissions of the role ')
        ielite_logger.info(permission_list)
        response_dict .update({'permission_list': permission_list})

        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript')
    except Exception as e:
        ielite_except_logger.critical('user_management \t get_group_permission \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(response_dict),
                            content_type='application/javascript', status=500)

#################* Newly added By Sam *#################


class get_role_level(View):
    def get(self,request):
        
        response_dict = {}
        try:
            # pdb.set_trace()
            values_list = []
            role_id = request.GET.get("ids")
            status = request.GET.get("status")
            values = request.user.users.user_userrolemaps.get(permanent_role = True)
            ct_obj = ContentType.objects
            role_m_id  = values.role_manager_id.content_type_id
            ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
            ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
            if ctz_pk == role_m_id:
                ct_id = RoleManager.objects.get(group_ptr__pk = role_id).content_type_id
                ct_obj = ContentType.objects.select_related().get(pk = ct_id)
                if ct_obj.model == "universitydetails":
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().values_list('pk','university_name'))
                elif ct_obj.model == "zonedetails":
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().filter(pk = request.user.users.object_id).values_list('pk','zone_name'))
                else:
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().filter(pk = request.user.users.object_id).values_list('pk','college_name'))
            
            elif ctu_pk == role_m_id:
                ct_id = RoleManager.objects.get(group_ptr__pk = role_id).content_type_id
                ct_obj = ContentType.objects.select_related().get(pk = ct_id)
                if ct_obj.model == "universitydetails":
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().values_list('pk','university_name'))
                elif ct_obj.model == "zonedetails":
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().values_list('pk','zone_name'))
                else:
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().values_list('pk','college_name'))
            else:
                ct_id = RoleManager.objects.get(group_ptr__pk = role_id).content_type_id
                ct_obj = ContentType.objects.select_related().get(pk = ct_id)
                if ct_obj.model == "universitydetails":
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().values_list('pk','university_name'))
                elif ct_obj.model == "zonedetails":
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().filter(pk = request.user.users.object_id).values_list('pk','zone_name'))
                else:
                    values_list = list(ContentType.objects.get(pk = ct_id).get_all_objects_for_this_type().filter(pk = request.user.users.object_id).values_list('pk','college_name'))
            
            response_dict.update({'values_list':values_list})
            ielite_logger.info('user_management \t get_role_level \t get the permissions of the role ')
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
        except Exception as e:
            # pass
            ielite_except_logger.critical('user_management \t get_role_level \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)

class role_check(View):
    def get(self,request):
        
        response_dict = {}
        try:
            # pdb.set_trace()
            role_name = request.GET.get("value")
            if Group.objects.filter(name__icontains = role_name).exists():
                response_dict.update({"flag":"true"})
            else:
                response_dict.update({"flag":"false"})
            ielite_logger.info("user_management \t role_check\t check the role name exist or not ")
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
        except Exception as e:
            ielite_except_logger.critical('user_management \t role_check\t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)


class user_check(View):
    def get(self,request):
        
        response_dict = {}
        try:
            # pdb.set_trace()
            user_id = request.GET.get("value")
            if User.objects.filter(username = user_id):
                response_dict.update({"flag":"true"})
            else:
                response_dict.update({"flag":"false"})
            ielite_logger.info("user_management \t user_check\t check the user name exist or not ")
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
        except Exception as e:
            # pass
            ielite_except_logger.critical('user_management \t user_check\t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)

class email_validation(View):
    def get(self,request):
        
        response_dict = {}
        try:
            # pdb.set_trace()
            email_id = request.GET.get("value")
            login_id = request.GET.get("login_id")
            try:
                user_obj = UserDetails.objects.filter(email_id = email_id,pk = login_id)
            except:
                user_obj = ""
            if user_obj:
                response_dict.update({"flag":"false"})
                ielite_logger.info("user_management \t user_check\t check the user Email exist ")
            else:
                user_obj = UserDetails.objects.filter(email_id = email_id)
                if user_obj:
                    response_dict.update({"flag":"true"})
                else:
                    response_dict.update({"flag":"false"})
                    ielite_logger.info("user_management \t user_check\t check the user Email exist ")
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
        except Exception as e:
            # pass
            ielite_except_logger.critical('user_management \t user_check\t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)

class remove_user_role(View):
    def post(self,request):
        response_dict = {}
        # pdb.set_trace()
        remove_id = request.POST.get("remove_id")
        urm_obj = UserRoleMap.objects.get(pk = remove_id)
        if urm_obj.status == False:
            urm_obj.status = True
        else:
            urm_obj.status = False

        urm_obj.save()
        response_dict.update({"status":urm_obj.status})
        ielite_logger.info("user_management \t remove_user_role\t remove the relation between user and role ")
        return HttpResponse(json.dumps(response_dict), 
            content_type='application/javascript',
            status=200)


def switch_roles(request):
    # pdb.set_trace()
    response_dict = {}
    context = {}
    r_id = request.POST.get("roleNames")
    role_obj = RoleManager.objects.get(group_ptr__pk = r_id)
    group_obj = request.user.groups.all()
    for each in group_obj:
        request.user.groups.remove(each)
    request.user.groups.add(role_obj)
    messages.add_message(request, messages.INFO, "Your Role Has Changed To "+str(role_obj.name))
    ielite_logger.info("user_management \t switch_roles\t switch roles if user has multiple roles")
    return HttpResponseRedirect("/")

def forgot_password(request):
    """This function is to perform forgot password
    :param name:request
    :param type: obj
    :returns:  dict, contains status.
    :raises: AttributeError, KeyError
    """
    context = {}
    try:

        email = request.POST.get("email")
        if User.objects.filter(username__icontains = email).exists():
            request.POST._mutable = True
            request.POST["email"] = User.objects.get(username = email).email
            request.POST._mutable = False
            password_reset(request,html_email_template_name='registration/password_reset_email.html',from_email = settings.EMAIL_HOST_USER)
            context.update({"status":"Set password link sent to registred email."})
        else:
            context.update({"status":"User is not registred!"})
        ielite_logger.info("user_management \t forgot_password\t sends email link to register user to set password")
    except:
        ielite_except_logger.critical('user_management \t forgot_password \t '+str(e) +'\n'+ str(traceback.format_exc()))
        context.update({"status":"Sorry!!, something went wrong"})
    return HttpResponse(json.dumps(context), 
            content_type='application/javascript',
            status=200)

def change_password(request):
    # pdb.set_trace()
    context = {}
    status = request.user.check_password(request.GET.get("old_password"))
    if status:
        u = User.objects.get(pk = request.user.pk)
        u.set_password(request.GET.get("new_password"))
        u.save()
    logout(request)
    messages.add_message(request, messages.INFO, "Your Password Changed Sucessfully! LOGIN AGAIN ")
    ielite_logger.info("user_management \t change_password \t User can change password")
    context.update({"status" : str(status)})
    return HttpResponse(json.dumps(context), 
            content_type='application/javascript',
            status=200)

def user_activate(request):
    # pdb.set_trace()
    context = {}
    status = True
    user_pk = request.GET.get("pk")
    user_object = User.objects
    if user_object.get(pk = user_pk).is_active:
        # user_object.filter(pk = user_pk).update(is_active = False)
        user_obj = user_object.get(pk = user_pk)
        user_obj.is_active = False
        user_obj.save()
    else:
        user_object.filter(pk = user_pk).update(is_active = True)
    context.update({"status" : str(user_object.get(pk = user_pk).is_active)})
    ielite_logger.info("user_management \t user_activate \t User Activate or Deactivate")
    return HttpResponse(json.dumps(context), 
            content_type='application/javascript',
            status=200)

def user_delete(request):
    # pdb.set_trace()
    context = {}
    try:
        status = True
        user_pk = request.GET.get("pk")
        user_object = User.objects
        user_object.filter(pk = user_pk).update(is_active = False)
        UserDetails.objects.filter(pk = user_pk).update(status = False,email_id = "")
        context.update({"status" : str(status)})
        ielite_logger.info("user_management \t user_delete \t User Delete")
    except:
        ielite_except_logger.critical('user_management \t user_delete \t '+str(e) +'\n'+ str(traceback.format_exc()))
    return HttpResponse(json.dumps(context), 
            content_type='application/javascript',
            status=200)

def delete_roles_privileges(request):
    # pdb.set_trace()
    context = {}
    try:
        status = True
        role_pk = request.GET.get("pk")
        role_object = RoleManager.objects
        role = role_object.get(group_ptr__pk = role_pk)
        role_object.filter(group_ptr__pk = role_pk).update(is_active = False,status = False)
        UserRoleMap.objects.filter(role_manager_id = role).update(is_active = False)
        for each in User.objects.filter(groups = role_pk):
            each.groups.remove(role)
            user_role_obj = UserRoleMap.objects.filter(user_details_id = each.users,is_active = True,permanent_role = True)
            if user_role_obj.exists():
                each.groups.add(user_role_obj[0].role_manager_id.group_ptr)
        context.update({"status" : str(status)})
        ielite_logger.info("user_management \t delete_roles_privileges \t role Delete")
        # messages.add_message(request, messages.INFO, "User deactivated sucessfully!")
    except:
        ielite_except_logger.critical('user_management \t delete_roles_privileges \t '+str(e) +'\n'+ str(traceback.format_exc()))
    return HttpResponse(json.dumps(context), 
            content_type='application/javascript',
            status=200)


def roles_privilege_active(request):
    # pdb.set_trace()
    context = {}
    try:
        status = True
        role_pk = request.GET.get("pk")
        role_object = RoleManager.objects
        role = role_object.get(group_ptr__pk = role_pk)
        if role.is_active:
            role_object.filter(group_ptr__pk = role_pk).update(is_active = False)
            UserRoleMap.objects.filter(role_manager_id = role).update(is_active = False)
            for each in User.objects.filter(groups = role_pk):
                each.groups.remove(role)
                user_role_obj = UserRoleMap.objects.filter(user_details_id = each.users,is_active = True,permanent_role = True)
                if user_role_obj.exists():
                    each.groups.add(user_role_obj[0].role_manager_id.group_ptr)
        else:
            role_object.filter(group_ptr__pk = role_pk).update(is_active = True)
            user_role_obj = UserRoleMap.objects.filter(role_manager_id = role)
            user_role_obj.update(is_active = True)
            for each in user_role_obj:
                if not each.user_details_id.user.groups.all().exists():
                    each.user_details_id.user.groups.add(each.role_manager_id.group_ptr)
        context.update({"status" : str(status)})
        ielite_logger.info("user_management \t roles_privilege_active \t User roles activate and deactivate")
        # messages.add_message(request, messages.INFO, "User deactivated sucessfully!")
    except:
        ielite_except_logger.critical('user_management \t roles_privilege_active \t '+str(e) +'\n'+ str(traceback.format_exc()))
    return HttpResponse(json.dumps(context), 
            content_type='application/javascript',
            status=200)

def check_password(request):
    # pdb.set_trace()
    context = {}
    status = request.user.check_password(request.GET.get("old_password"))
    context.update({"status" : str(status)})
    ielite_logger.info("user_management \t check_password \t Used in change password to check old password is correct or not")
    return HttpResponse(json.dumps(context), 
            content_type='application/javascript',
            status=200)
# from programme_management.models import *
class usermanagement(View):
    def get(self,request):
        context = {}
        try:
            
            ct_obj = ContentType.objects
            ct_id = ct_obj.get(model = "universitydetails").pk
            zone_user_list =list(RoleManager.objects.filter(content_type_id = 70).values_list("pk",flat = True))
            user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
            user_object = UserDetails.objects.filter(pk__in = user_list)
            # session_subject= ProgrammeCycleMap.objects.select_related().filter(status=True).distinct("programme_cycle_map_id").order_by('-programme_cycle_map_id')
            # context.update({"dummy":session_subject,"user_object":user_object,})
            context.update({"user_object":user_object,"user_key":"User","role_key":"RolesPrivilege"})
            context.update({"content":content.contents["university"]})
            ielite_logger.info("user_management \t usermanagement \t load user management main page")
            return render(request, "new_include/user_management.html",content_type='text/html',context=context)
            # return render(request, "data_tables.html",content_type='text/html',context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t usermanagement \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/user_management.html",context=context)

    def post(self,request):
        pass
################ methods #######################
def generate_device_id():
    # start = 10**(n-1)
    # end = (10**n)-1
    passcode = randint(100000,999999)
    while True:
        device_user_id = randint(100000,999999)
        if not UserDetails.objects.filter(device_user_id = device_user_id).exists() and passcode%10:
            break
    return device_user_id,passcode


def edit_all_user(req,user_object):
    ## function to get edit values for all users ##
    response_dict = {}
    try:
        ct_obj = ContentType.objects
        get_data = req.GET
        user_id = req.GET.get("ids")
        level = []
        for e in user_object.user_userrolemaps.select_related().order_by('created_on'):
            if e.role_manager_id.content_type_id == ct_obj.get(model = "universitydetails").pk:
                level.append(list(e.role_manager_id.content_type.get_all_objects_for_this_type().filter(pk = e.object_id).values_list('pk','university_name')))
            if e.role_manager_id.content_type_id == ct_obj.get(model = "zonedetails").pk:
                level.append(list(e.role_manager_id.content_type.get_all_objects_for_this_type().filter(pk = e.object_id).values_list('pk','zone_name')))
            if e.role_manager_id.content_type_id == ct_obj.get(model = "collegedetails").pk:
                level.append(list(e.role_manager_id.content_type.get_all_objects_for_this_type().filter(pk = e.object_id).values_list('pk','college_name')))

        response_dict.update({
        "title":user_object.title,
        "user_id":user_object.user.username,
        "firstname":user_object.first_name,
        "lastname":user_object.last_name,
        "address1":user_object.address1,
        "address2":user_object.address2,
        "phone_no":user_object.phone_no,
        "fax_no" :user_object.fax_no,
        "user_id" :user_object.user.username,
        "specialization":user_object.specialization,
        "qualification":user_object.qualification,
        "designation":user_object.designation,
        "description":user_object.description,
        "experience":user_object.experience,
        "gender":[(i,j) for i,j in user_object.GENDER_CHOICES if i == user_object.gender],
        "email":user_object.user.email,    
        "roles":list(RoleManager.objects.filter(role_userrolemaps__user_details_id=user_id).order_by("role_userrolemaps__created_on").values_list("name","group_ptr__pk")),
        "user_role_edit_pk": list(user_object.user_userrolemaps.order_by("created_on").values_list("pk",flat = True)) ,
        "start_date":[each.date().strftime('%d-%m-%Y') for each in list(user_object.user_userrolemaps.values_list("start_time",flat = True)) ],
        "end_date":[each.date().strftime('%d-%m-%Y') for each in list(user_object.user_userrolemaps.values_list("end_time",flat = True)) ],
        "level_name":level,
          })
        ielite_logger.info("user_management \t edit_all_user \t to get edit instance of all user")
    except Exception as e:
            ielite_except_logger.critical('user_management \t edit_all_user \t '+str(e) +'\n'+ str(traceback.format_exc()))
    return response_dict

def add_edit_delete_user(req):
    ''' in this function start_time, end_time code is commented by naveen ,because we are giving optionl field for start,end time from front-end'''
    request = req
    response_dict = {}
    date_now = datetime.datetime.now()
    dob = pytz.utc.localize(date_now)
    variable_dict = {
    "address1":"",
    "address2":"",
    "fax_no":1,
    "designation":"",
    "qualification":"",
    "experience":0,
    "specialization":"",
    "description":"",
    "slug":"",
    }
    datas = request.POST
    # datas = urllib.parse.parse_qs(post_data['form_data'])
    
    f_name = datas.get("f_name")
    l_name = datas.get("l_name")
    ph_no = datas.get("ph_no")
    email_id = datas.get("email")
    s_date = datas.get("s_date")
    e_date = datas.get("e_date")
    role_id = datas.get("role_id").split(",")
    gender = datas.get("gender_val")
    u_obj_id = datas.get("u_obj_id")
    ct_id = datas.get("ct_id").split(",")
    urm_edit_id = datas.get("urm_edit_id").split(",")
    title = datas.get("title")
    for each in variable_dict:

        if datas.get(each):
            variable_dict[each] = datas.get(each)

    ### commented by naveen ########
    # s_date = datas.get("s_date").split(",")
    # e_date = datas.get("e_date").split(",")
    ########## #########################

    if datas.get("status") == "edit":
        # pdb.set_trace()
        edit_id = datas.get("edit_id")
        usd_obj = UserDetails.objects.get(pk = edit_id)
        User.objects.filter(pk = usd_obj.user.pk).update(email = email_id)
        # usd.user_id.username = login_id
        # usd.save()
        usd = UserDetails.objects.filter(pk = edit_id)
        response_dict.update({"mag_status":"edit"})
        usd.update(
            title=int(title),
            first_name=f_name, 
            last_name = l_name,
            address1 = variable_dict.get("address1"),
            address2 = variable_dict.get("address2"),
            phone_no = ph_no,
            fax_no = variable_dict.get("fax_no"),
            # user = user,
            email_id = email_id,
            gender = int(gender),
            qualification = variable_dict.get("qualification"),
            designation = variable_dict.get("designation"),
            experience = variable_dict.get("experience"),
            specialization = variable_dict.get("specialization"),
            description = variable_dict.get("description"),
            photo = "",
            signature = "",
            object_id = 1,
            created_by = request.user.pk,
            dob = dob,
            )
        cnt = 0
        p_role = 1

        for each in role_id:
            usd[0].roles.add = RoleManager.objects.get(group_ptr__pk=each)
            ## commented by naveen ########
            # st_date = datetime.datetime.strptime(s_date[cnt],'%d-%m-%Y')
            # en_date = datetime.datetime.strptime(e_date[cnt],'%d-%m-%Y')
            # days_val = (st_date.date() - date_now.date()).days
            # st_date = pytz.utc.localize(st_date)
            # en_date = pytz.utc.localize(en_date)
            ############################ ###################################
            try:
                user_role_obj = UserRoleMap.objects.filter(pk = urm_edit_id[cnt])
            except:
                user_role_obj = ""
            if user_role_obj:
                user_role_obj.update(
                    user_details_id = usd[0], 
                    role_manager_id = RoleManager.objects.get(group_ptr__pk=each), 
                    # end_time = en_date,
                    # start_time = st_date,
                    # priority_role=priority,
                    object_id = ct_id[cnt],
                    is_active = True,
                    # permanent_role = p_role,
                    created_by = request.user.pk,
                    )
                ###### commented by naveen ###############
                # if days_val <= 0 :
                #     user_role_obj.update(
                #         status = True, 
                #         )
                # else:
                ################### #############
                user_role_obj.update(
                        status=False,
                        )
                p_role = 0
                
            else:
                user_role_objs = UserRoleMap.objects.create(
                        status=True, 
                        user_details_id=usd[0], 
                        role_manager_id=RoleManager.objects.get(group_ptr__pk=each), 
                        # end_time = en_date,
                        # start_time = st_date,
                        priority_role=False,
                        object_id = ct_id[cnt],
                        is_active = True,
                        permanent_role = False,
                        created_by = request.user.pk,
                        )
                if days_val > 0 :
                    user_role_objs.status = False
                user_role_objs.save()
                p_role = 0
            cnt = cnt + 1
    else:
        # pdb.set_trace()
        login_id = datas.get("login_id")
        device_user_id,passcode = generate_device_id()
        user = User.objects.create_user(login_id.lower(),email_id,"user@12345")
        user.save()
        response_dict.update({"mag_status":"add"})
        usd = UserDetails(
            title=1,
            first_name=login_id, 
            last_name = l_name,
            address1 = variable_dict.get("address1"),
            address2 = variable_dict.get("address2"),
            phone_no = 1231231231,
            fax_no = variable_dict.get("fax_no"),
            user = user,
            email_id = email_id,
            gender = 1,
            qualification = variable_dict.get("qualification"),
            designation = variable_dict.get("designation"),
            experience = variable_dict.get("experience"),
            specialization = variable_dict.get("specialization"),
            description = variable_dict.get("description"),
            photo = "",
            signature = "",
            object_id = 1,
            created_by = request.user.pk,
            # created_by = 1,
            dob = dob,
            device_user_id = device_user_id,
            passcode = passcode,
            )
        usd.save()
        # role_obj = RoleManager.objects.filter(pk__in=role_id)
        p_role = 1
        cnt = 0
        for each in role_id:
            if p_role:
                user.groups.add(RoleManager.objects.get(group_ptr__pk=each))
            usd.roles.add = RoleManager.objects.get(group_ptr__pk=each)
            ##### commented by naveen #######################
            # st_date = datetime.datetime.strptime(s_date[cnt],'%d-%m-%Y')
            # en_date = datetime.datetime.strptime(s_date[cnt],'%d-%m-%Y')
            # days_val = (st_date.date() - date_now.date()).days
            # st_date = pytz.utc.localize(st_date)
            # en_date = pytz.utc.localize(en_date)
            
            # if days_val <= 0:
            #     UserRoleMap(
            #         status=True, 
            #         user_details_id=usd, 
            #         role_manager_id=RoleManager.objects.get(group_ptr__pk=each), 
            #         # end_time = en_date,
            #         # start_time = st_date,
            #         priority_role=True,
            #         object_id = ct_id[cnt],
            #         is_active = True,
            #         permanent_role = p_role,
            #         created_by = request.user.pk,
            #         ).save()
            # else:
            ################ #########################
            UserRoleMap(
                    status=False, 
                    user_details_id=usd, 
                    role_manager_id=RoleManager.objects.get(group_ptr__pk=each),
                    # end_time = en_date,
                    # start_time = st_date,
                    priority_role=True,
                    object_id = ct_id[cnt],
                    is_active = True,
                    permanent_role = p_role,
                    created_by = request.user.pk,
                    ).save()
            cnt = cnt + 1
            p_role = 0
        # pdb.set_trace()
        # send_activation_mail.delay(request,settings.EMAIL_HOST_USER)
        # save_user_terms_conditions(request,variable_dict.get("slug"))
        #pdb.set_trace()
        password_reset(request,html_email_template_name='registration/password_reset_email.html',from_email = settings.EMAIL_HOST_USER)
        ielite_logger.info("user_management \t add_edit_delete_user \t add edit delete user")
        ielite_logger.info("mail sucessfully sent")
    return response_dict
##################### methods over ##########################
# @method_decorator(csrf_exempt, name='dispatch')
class university_users(View):
    def get(self,request):
        context = {}
        try:
            ct_obj = ContentType.objects
            get_data = request.GET
            response_dict = {}
            if get_data.get("status") == "get_user":
                user_id = request.GET.get("ids")
                user_object = UserDetails.objects.select_related().get(pk = user_id)
                response_dict = edit_all_user(request,user_object)
                response_dict.update({"university":list(user_object.user_userrolemaps.get(permanent_role = True).role_manager_id.content_type.get_all_objects_for_this_type().values_list("pk","university_name")),})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                ct_obj = ContentType.objects
                ct_id = ct_obj.get(model = "universitydetails").pk
                zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                user_object = UserDetails.objects.filter(pk__in = user_list,status = True).exclude(pk = request.user.users.pk).order_by("-created_on")
                context.update({"level_name":"University","load_url":"forms_university/",
                    "user_object":user_object})
                ielite_logger.info("user_management \t university_users \t load user university level user grid page")
                return render(request, "new_include/user_new.html",content_type='text/html',context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t university_users \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/user_new.html",context=context)

    def post(self,request):
        response_dict = {}
        try:
            # pdb.set_trace()
            response_dict = add_edit_delete_user(request)            
            # send_mail('User Creation Conformation', "Dear user,\n\n Congratulations your account is created with, \n user id: "+'login_id' +"\n\n Thank you\n",settings.EMAIL_HOST_USER,['samith@mindlogicx.com'], fail_silently=False)
            ielite_logger.info("user_management \t university_users \t post method to store the user data")

            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)
        except Exception as e:
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

def forms_university(request):
    context = {}
    try:
        ct_obj = ContentType.objects
        get_data = request.GET
        response_dict = {}
        if get_data.get("status") == "get_user":
            user_id = request.GET.get("ids")
            user_object = UserDetails.objects.select_related().get(pk = user_id)
            response_dict = edit_all_user(request,user_object)
            response_dict.update({"university":list(user_object.user_userrolemaps.get(permanent_role = True).role_manager_id.content_type.get_all_objects_for_this_type().values_list("pk","university_name")),})
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)
        else:
            # pdb.set_trace()
            z_roles = ""
            c_roles = ""
            u_roles = ""
            ct_obj = ContentType.objects
            ct_id = ct_obj.get(model = "universitydetails").pk
            zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
            user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
            user_object = UserDetails.objects.filter(pk__in = user_list,status = True).exclude(pk = request.user.users.pk)
            val = RoleManager.objects.select_related()
            role_obj = val.all().values_list("content_type_id",flat=True).distinct()
            for each in role_obj:
                if int(each) == ct_obj.get(model = "universitydetails").pk:
                    u_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                if int(each) == ct_obj.get(model = "zonedetails").pk:
                    z_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                if int(each) == ct_obj.get(model = "collegedetails").pk:
                    c_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
            # response_dict.update({'u_role':})

            context.update({"GENDER_CHOICES":UserDetails.GENDER_CHOICES,"PROFESSION_TITLE":PROFESSION_TITLE,"edit_instance":"university_users","add_edit_url":"university_users","user_object":user_object,"u_role_object":u_roles,"z_role_object":z_roles,"c_role_object":c_roles})
            ielite_logger.info("user_management \t forms_university \t load user university level user form page")
    except Exception as e:
        pass
    return render(request, "new_include/forms/user_form.html",context=context)

class roles_privilege(View):
    def get(self,request):
        
        context = {}
        response_dict = {}
        try:
            get_data = request.GET
            if get_data.get("status") == "get_roles":
                # pdb.set_trace()
                rm_obj = RoleManager.objects.get(group_ptr__pk = get_data.get("get_id"))
                per_list = list(rm_obj.permissions.values_list("content_type_id","codename"))
                response_dict.update({"per_list" : per_list,"name":str(rm_obj.name),
                    "role_level":rm_obj.content_type.name,"role_id":rm_obj.content_type.pk})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                ct_obj = ContentType.objects
                ct_id = ct_obj.get(model = "universitydetails").pk
                user_role_list = list(request.user.users.user_userrolemaps.all().values_list("role_manager_id",flat = True))
                user_role_list = RoleManager.objects.filter(pk__in = user_role_list).values_list('group_ptr_id',flat = True)
                role_object = RoleManager.objects.filter(content_type = ct_id,status = True).exclude(group_ptr__pk__in = user_role_list).order_by("-created_on")
                c_objects = ConfigMaster.objects.all()
                #permission_obj = Permission.objects.filter(content_type_id=71).values_list("name","pk")[2:]
                context.update({"role_form_url":"roles_forms","role_object":role_object,"c_objects":c_objects})
                ielite_logger.info("user_management \t roles_privilege \t get method to load user university level roles privilege form page")
                return render(request, "new_include/role_privileges.html",content_type='text/html',context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t roles_privilege \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/role_privileges.html",context=context)


    def post(self,request):
        response_dict = {}
        temp_list = [[],[],[],[],[],[],[],[]]
        view_list = []
        add_list = []
        edit_list = []
        delete_list = []
        get_view_list = []
        get_add_list = []
        get_edit_list = []
        get_delete_list = []
        post_data = request.POST
        try:
            # pdb.set_trace()
            if post_data.get('role_status') == 'add':
                datas = post_data
                role_name = post_data.get("role_name")
                rm_obj = RoleManager(
                    content_type = ContentType.objects.get(app_label='college_management',model = "universitydetails"),
                    name = role_name,
                    created_by = 1,
                )
                rm_obj.save()
                #pdb.set_trace()
                view_list.extend(datas.getlist('view') if datas.getlist('view') else [])
                add_list.extend(datas.getlist('add') if datas.getlist('add') else [])
                edit_list.extend(datas.getlist('edit') if datas.getlist('edit') else [] )
                delete_list.extend(datas.getlist('delete') if datas.getlist('delete') else [])

                main_list = {0:add_list,1:edit_list,2:delete_list,3:view_list}
                p_obj = Permission.objects
                for each in main_list:
                    for view_id in main_list[each]:
                        view_obj  = p_obj.filter(content_type_id = int(view_id))[each]
                        rm_obj.permissions.add(view_obj)

                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                # pdb.set_trace()
                datas = request.POST
                role_name = datas.get("role_name")
                edit_id = int(datas.get('u_r_edit_id'))
                rm_obj = RoleManager.objects.get(group_ptr__pk = edit_id)
                rm_obj.name = role_name
                rm_obj.save()
                view_list.extend(datas.getlist('view') if datas.getlist('view') else [])
                add_list.extend(datas.getlist('add') if datas.getlist('add') else [])
                edit_list.extend(datas.getlist('edit') if datas.getlist('edit') else [] )
                delete_list.extend(datas.getlist('delete') if datas.getlist('delete') else [])

                rm_obj = RoleManager.objects.get(group_ptr__pk = edit_id)
                get_view_list.extend(list(rm_obj.permissions.filter(codename__contains = "view").values_list("content_type_id",flat=True)))
                get_add_list.extend(list(rm_obj.permissions.filter(codename__contains = "add").values_list("content_type_id",flat=True)))
                get_edit_list.extend(list(rm_obj.permissions.filter(codename__contains = "change").values_list("content_type_id",flat=True)))
                get_delete_list.extend(list(rm_obj.permissions.filter(codename__contains = "delete").values_list("content_type_id",flat=True)))

                get_list = [get_add_list,get_edit_list,get_delete_list,get_view_list]
                main_list = {0:add_list,1:edit_list,2:delete_list,3:view_list}
                p_obj = Permission.objects
                for each in main_list:
                    if main_list[each]:
                        adding_list = [item for item in main_list[each] if int(item) not in get_list[each]]
                        if adding_list:
                            for view_id in adding_list:
                                view_obj  = p_obj.filter(content_type_id = view_id)[each]
                                rm_obj.permissions.add(view_obj)
                    if get_list[each]:
                        remove_list = [item for item in get_list[each] if str(item) not in main_list[each]]
                        if remove_list:
                            for view_id in remove_list:
                                view_obj  = p_obj.filter(content_type_id = view_id)[each]
                                rm_obj.permissions.remove(view_obj)
                ielite_logger.info("user_management \t roles_privilege \t post method to store university level roles privilege")
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)

        except Exception as e:
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

def roles_forms(request):
    context = {}
    response_dict = {}
    try:
        get_data = request.GET
        if get_data.get("status") == "get_roles":
            #pdb.set_trace()
            rm_obj = RoleManager.objects.get(group_ptr__pk = get_data.get("get_id"))
            per_list = list(rm_obj.permissions.values_list("content_type_id","codename"))
            response_dict.update({"per_list" : per_list,"name":str(rm_obj.name),
                "role_level":rm_obj.content_type.name,"role_id":rm_obj.content_type.pk})
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)
        else:
            ct_obj = ContentType.objects
            ct_id = ct_obj.get(model = "universitydetails").pk
            user_role_list = list(request.user.users.user_userrolemaps.all().values_list("role_manager_id",flat = True))
            user_role_list = RoleManager.objects.filter(pk__in = user_role_list).values_list('group_ptr_id',flat = True)
            role_object = RoleManager.objects.filter(content_type = ct_id,status = True).exclude(group_ptr__pk__in = user_role_list)
            c_objects = ConfigMaster.objects.all()
            #permission_obj = Permission.objects.filter(content_type_id=71).values_list("name","pk")[2:]
            context.update({"roles_privilege":"roles_privilege","role_object":role_object,"c_objects":c_objects})
        ielite_logger.info("user_management \t roles_forms \t method to store university level roles privilege form page")
    except Exception as e:
        ielite_except_logger.critical('user_management \t roles_forms \t' + str(e) +'\n'+ str(traceback.format_exc()))
    return render(request, "new_include/forms/roles_privilege_form.html",context=context)

class zone_usermanagement(View):

    def get(self,request):
        context = {}
        try:
            # pdb.set_trace()
            ct_obj = ContentType.objects
            ct_id = ct_obj.get(app_label='college_management',model = "zonedetails").pk
            zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
            user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list).values_list("user_details_id",flat = True))
            user_object = UserDetails.objects.filter(pk__in = user_list)
            
            context.update({"user_object":user_object,"user_key":"ZoneUser","role_key":"ZoneRolesPrivilege"})
            context.update({"content":content.contents["zone"]})
            ielite_logger.info("user_management \t zone_usermanagement \t get method to load zone level user grid page")
            return render(request, "new_include/user_management.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t zone_usermanagement \t'+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/user_management.html",context=context)


def forms_zone(request):

        context = {}
        try:
            ct_obj = ContentType.objects
            get_data = request.GET
            response_dict = {}
            if get_data.get("status") == "get_user":
                user_id = request.GET.get("ids")
                user_object = UserDetails.objects.select_related().get(pk = user_id)
                response_dict = edit_all_user(request,user_object)
                response_dict.update({"university":list(user_object.user_userrolemaps.get(permanent_role = True).role_manager_id.content_type.get_all_objects_for_this_type().values_list("pk","zone_name")),})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                # pdb.set_trace()
                # values = request.user.users.user_userrolemaps.get(permanent_role = True)
                group_pk = request.user.groups.get().pk
                role_m_id  = RoleManager.objects.get(group_ptr__pk = group_pk).content_type_id
                ct_obj = ContentType.objects
                # rolelist = list(request.user.users.roles.all().values_list('content_type_id',flat=True))
                # role_m_id  = values.role_manager_id.content_type_id
                
                ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
                ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                c_objects = ConfigMaster.objects.all()
                if ctu_pk == role_m_id:
                    z_roles = ""
                    c_roles = ""
                    u_roles = ""
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    for each in role_obj:
                        if int(each) == ct_obj.get(model = "universitydetails").pk:
                            u_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "zonedetails").pk:
                            z_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "collegedetails").pk:
                            c_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                    # response_dict.update({'u_role':})
                    zone_object = ZoneDetails.objects.all()
                    context.update({"GENDER_CHOICES":UserDetails.GENDER_CHOICES,"PROFESSION_TITLE":PROFESSION_TITLE,"edit_instance":"users_zoneu","add_edit_url":"users_zoneu",
                        "zone_object":zone_object,"user_object":user_object,
                        "z_role_object":u_roles,"u_role_object":z_roles,"c_role_object":c_roles})
                    return render(request, "new_include/forms/user_form.html",context=context)
                else:
                    z_roles = ""
                    c_roles = ""
                    u_roles = ""
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    for each in role_obj:
                        # if int(each) == 16:
                        #     u_roles=val.filter(content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "zonedetails").pk:
                            z_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "collegedetails").pk:
                            c_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                    # response_dict.update({'u_role':})
                    zone_object = ZoneDetails.objects.filter(pk = request.user.users.object_id)
                    context.update({"GENDER_CHOICES":UserDetails.GENDER_CHOICES,"PROFESSION_TITLE":PROFESSION_TITLE,"edit_instance":"users_zoneu","add_edit_url":"users_zoneu","zone_object":zone_object,"user_object":user_object,"u_role_object":u_roles,"z_role_object":z_roles,"c_role_object":c_roles})
                    ielite_logger.info("user_management \t forms_zone \t get method to load zone level user grid page")
                    return render(request, "new_include/forms/user_form.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t forms_zone \t'+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/forms/user_form.html",context=context)


class zone_users(View):
    def get(self,request):
        context = {}
        try:
            ielite_logger.info("user_management \t zone_users \t get method to load zone level user grid page")
            ct_obj = ContentType.objects
            get_data = request.GET
            response_dict = {}
            if get_data.get("status") == "get_user":
                user_id = request.GET.get("ids")
                user_object = UserDetails.objects.select_related().get(pk = user_id)
                response_dict = edit_all_user(request,user_object)
                response_dict.update({"university":list(user_object.user_userrolemaps.get(permanent_role = True).role_manager_id.content_type.get_all_objects_for_this_type().values_list("pk","zone_name")),})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                # pdb.set_trace()
                # values = request.user.users.user_userrolemaps.get(permanent_role = True)
                group_pk = request.user.groups.get().pk
                role_m_id  = RoleManager.objects.get(group_ptr__pk = group_pk).content_type_id
                ct_obj = ContentType.objects
                # rolelist = list(request.user.users.roles.all().values_list('content_type_id',flat=True))
                # role_m_id  = values.role_manager_id.content_type_id
                
                ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
                ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                c_objects = ConfigMaster.objects.all()
                if ctu_pk == role_m_id:

                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True)


                    context.update({"level_name":"Zone","load_url":"forms_zone/",
                        "user_object":user_object})
                    return render(request, "new_include/user_new.html",context=context)
                else:

                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    
                    context.update({"level_name":"Zone","load_url":"forms_zone/",
                        "user_object":user_object})
                    return render(request, "new_include/user_new.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t zone_users \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/user_new.html",context=context)

    def post(self,request):
        response_dict = {}
        try:
            response_dict = add_edit_delete_user(request)
            ielite_logger.info("user_management \t zone_users \t post method to store zone level user data")
            #send_mail('User Creation Conformation', "Dear user,\n\n Congratulations your account is created with, \n user id: "+login_id +"\n\n Thank you\n",settings.EMAIL_HOST_USER,[email_id], fail_silently=False)
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)
        except Exception as e:
            ielite_except_logger.critical('user_management \t zone_users \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)


class roles_privilege_zone(View):
    def get(self,request):
        context = {}
        response_dict = {}
        try:
            get_data = request.GET
            if get_data.get("status") == "get_roles":
                ielite_logger.info("user_management \t roles_privilege_zone \t get method to load zone level roles privilege  data")
                rm_obj = RoleManager.objects.get(group_ptr__pk = get_data.get("get_id"))
                per_list = list(rm_obj.permissions.values_list("content_type_id","codename"))
                ct_obj_list = request.user.users.user_userrolemaps.select_related().values_list("object_id",flat = True)
                # zone_object = Zone.objects.filter(pk__in = ct_obj_list).values_list()
                response_dict.update({"per_list" : per_list,"name":str(rm_obj.name),
                    "role_level":rm_obj.content_type.name,"role_id":rm_obj.content_type.pk})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                ct_obj = ContentType.objects
                rolelist = list(request.user.users.roles.all().values_list('content_type_id',flat=True))
                ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
                ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                c_objects = ConfigMaster.objects.all()
                user_role_list = list(request.user.users.user_userrolemaps.all().values_list("role_manager_id",flat = True))
                
                if ctu_pk in rolelist:
                    # pdb.set_trace()
                    ct_id = ctz_pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list).values_list("user_details_id",
                        flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list)
                    role_object = RoleManager.objects.filter(content_type = ct_id,status = True).exclude(group_ptr__pk__in = user_role_list)
                    coll_object = CollegeDetails.objects.all()
                    zone_object = ZoneDetails.objects.all()
                elif ctz_pk in rolelist:
                    #pdb.set_trace()
                    user_list = list(request.user.userdetails.user_role_map.filter(priority=1).values_list("user_details_id",
                        flat = True))
                    ct_obj_list = request.user.userdetails.roles.select_related().values_list("object_id",flat = True)
                    ct_id = ctz_pk
                    user_object = UserDetails.objects.filter(pk__in = user_list)
                    role_object = RoleManager.objects.filter(content_type = ct_id,status = True,object_id__in = ct_obj_list).exclude(group_ptr__pk__in = user_role_list)
                    
                    zone_object = ZoneDetails.objects.filter(pk = ct_obj_list)
                    # coll_object = CollegeDetails.objects.filter(zone = zone_object[0].pk)

                context.update({"role_form_url":"wzone_roles_formsw","role_object":role_object,"c_objects":c_objects,"zone_object":zone_object})
                return render(request, "new_include/role_privileges.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t roles_privilege_zone \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/role_privileges.html",context=context)


    def post(self,request):
        # pdb.set_trace()
        response_dict = {}
        temp_list = [[],[],[],[],[],[],[],[]]
        view_list = []
        add_list = []
        edit_list = []
        delete_list = []
        get_view_list = []
        get_add_list = []
        get_edit_list = []
        get_delete_list = []
        post_data = request.POST
        try:
            if post_data.get('role_status') == 'add':
                datas = request.POST
                role_name = post_data.get("role_name")
                rm_obj = RoleManager(
                    content_type = ContentType.objects.get(app_label='college_management',model = "zonedetails"),
                    name = role_name,
                    created_by = 1,
                )
                rm_obj.save()
                #pdb.set_trace()

                view_list.extend(datas.getlist('view') if datas.getlist('view') else [])
                add_list.extend(datas.getlist('add') if datas.getlist('add') else [])
                edit_list.extend(datas.getlist('edit') if datas.getlist('edit') else [] )
                delete_list.extend(datas.getlist('delete') if datas.getlist('delete') else [])

                main_list = {0:add_list,1:edit_list,2:delete_list,3:view_list}
                p_obj = Permission.objects
                for each in main_list:
                    for view_id in main_list[each]:
                        view_obj  = p_obj.filter(content_type_id = int(view_id))[each]
                        rm_obj.permissions.add(view_obj)

                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                #pdb.set_trace()
                datas = request.POST
                role_name = post_data.get("role_name")
                edit_id = int(datas.get('u_r_edit_id'))
                rm_obj = RoleManager.objects.get(group_ptr__pk = edit_id)
                rm_obj.name = role_name
                rm_obj.save()
                view_list.extend(datas.getlist('view') if datas.getlist('view') else [])
                add_list.extend(datas.getlist('add') if datas.getlist('add') else [])
                edit_list.extend(datas.getlist('edit') if datas.getlist('edit') else [] )
                delete_list.extend(datas.getlist('delete') if datas.getlist('delete') else [])

                rm_obj = RoleManager.objects.get(group_ptr__pk = edit_id)
                get_view_list.extend(list(rm_obj.permissions.filter(codename__contains = "view").values_list("content_type_id",flat=True)))
                get_add_list.extend(list(rm_obj.permissions.filter(codename__contains = "add").values_list("content_type_id",flat=True)))
                get_edit_list.extend(list(rm_obj.permissions.filter(codename__contains = "change").values_list("content_type_id",flat=True)))
                get_delete_list.extend(list(rm_obj.permissions.filter(codename__contains = "delete").values_list("content_type_id",flat=True)))

                get_list = [get_add_list,get_edit_list,get_delete_list,get_view_list]
                main_list = {0:add_list,1:edit_list,2:delete_list,3:view_list}
                p_obj = Permission.objects
                for each in main_list:
                    if main_list[each]:
                        adding_list = [item for item in main_list[each] if int(item) not in get_list[each]]
                        if adding_list:
                            for view_id in adding_list:
                                view_obj  = p_obj.filter(content_type_id = view_id)[each]
                                rm_obj.permissions.add(view_obj)
                    if get_list[each]:
                        remove_list = [item for item in get_list[each] if str(item) not in main_list[each]]
                        if remove_list:
                            for view_id in remove_list:
                                view_obj  = p_obj.filter(content_type_id = view_id)[each]
                                rm_obj.permissions.remove(view_obj)
                ielite_logger.info("user_management \t roles_privilege_zone \t post method to store zone level roles privilege data")
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)

        except Exception as e:
            ielite_except_logger.critical('user_management \t roles_privilege_zone \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

def zone_roles_forms(request):
        # pdb.set_trace()
        context = {}
        response_dict = {}
        try:
            get_data = request.GET
            if get_data.get("status") == "get_roles":
                # pdb.set_trace()
                rm_obj = RoleManager.objects.get(group_ptr__pk = get_data.get("get_id"))
                per_list = list(rm_obj.permissions.values_list("content_type_id","codename"))
                ct_obj_list = request.user.users.user_userrolemaps.select_related().values_list("object_id",flat = True)
                # zone_object = Zone.objects.filter(pk__in = ct_obj_list).values_list()
                response_dict.update({"per_list" : per_list,"name":str(rm_obj.name),
                    "role_level":rm_obj.content_type.name,"role_id":rm_obj.content_type.pk})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                
                ct_obj = ContentType.objects
                rolelist = list(request.user.users.roles.all().values_list('content_type_id',flat=True))
                ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
                ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                c_objects = ConfigMaster.objects.all()
                user_role_list = list(request.user.users.user_userrolemaps.all().values_list("role_manager_id",flat = True))
                
                if ctu_pk in rolelist:
                    # pdb.set_trace()
                    ct_id = ctz_pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list).values_list("user_details_id",
                        flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list)
                    role_object = RoleManager.objects.filter(content_type = ct_id,status = True).exclude(group_ptr__pk__in = user_role_list)
                    coll_object = CollegeDetails.objects.all()
                    zone_object = ZoneDetails.objects.all()
                elif ctz_pk in rolelist:
                    #pdb.set_trace()
                    user_list = list(request.user.userdetails.user_role_map.filter(priority=1).values_list("user_details_id",
                        flat = True))
                    ct_obj_list = request.user.userdetails.roles.select_related().values_list("object_id",flat = True)
                    ct_id = ctz_pk
                    user_object = UserDetails.objects.filter(pk__in = user_list)
                    role_object = RoleManager.objects.filter(content_type = ct_id,status = True,object_id__in = ct_obj_list).exclude(group_ptr__pk__in = user_role_list)
                    
                    zone_object = ZoneDetails.objects.filter(pk = ct_obj_list)
                    # coll_object = CollegeDetails.objects.filter(zone = zone_object[0].pk)

                context.update({"roles_privilege":"roles_privilege_zoner",
                    "role_object":role_object,"c_objects":c_objects,"zone_object":zone_object})
                ielite_logger.info("user_management \t zone_roles_forms \t method to load zone level roles privilege form page")
                return render(request, "new_include/forms/roles_privilege_form.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t zone_roles_forms \t'+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/forms/roles_privilege_form.html",context=context)

############## college #########

class college_usermanagements(View):
    
    def get(self,request):
        context = {}
        try:
            # pdb.set_trace()
            ct_obj = ContentType.objects
            ct_id = ct_obj.get(app_label='college_management', model = "universitydetails").pk
            zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("pk",flat = True))
            user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list).values_list("user_details_id",flat = True))
            user_object = UserDetails.objects.filter(pk__in = user_list)
            
            context.update({"user_object":user_object,"user_key":"CollegeUser","role_key":"CollegeRolesPrivilege"})
            context.update({"content":content.contents["college"]})
            ielite_logger.info("user_management \t college_usermanagements \t get method to load college level user page")
            return render(request, "new_include/user_management.html",context=context)
        except Exception as e:
            pass
            ielite_except_logger.critical('user_management \t college_usermanagements \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/user_management.html",context=context)


class college_users_college(View):
    def get(self,request):
        context = {}
        try:
            # pdb.set_trace()
            ct_obj = ContentType.objects
            get_data = request.GET
            response_dict = {}
            ielite_logger.info("user_management \t college_users_college \t get method to load college level user page")
            if get_data.get("status") == "get_user":
                user_id = request.GET.get("ids")
                user_object = UserDetails.objects.select_related().get(pk = user_id)
                response_dict = edit_all_user(request,user_object)
                response_dict.update({"university":list(user_object.user_userrolemaps.get(permanent_role = True).role_manager_id.content_type.get_all_objects_for_this_type().values_list("pk","college_name")),})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                ct_obj = ContentType.objects
                group_pk = request.user.groups.get().pk
                role_m_id  = RoleManager.objects.get(group_ptr__pk = group_pk).content_type_id
                ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
                ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                if ctu_pk == role_m_id:
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    context.update({"level_name":"College","load_url":"forms_college/","user_object":user_object})
                    return render(request, "new_include/user_new.html",context=context)
                
                elif ctz_pk == role_m_id:
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True,object_id = request.user.users.object_id)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    context.update({"level_name":"College","load_url":"forms_college/",
                        "user_object":user_object})
                    return render(request, "new_include/user_new.html",context=context)
                else:
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True,object_id = request.user.users.object_id)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    context.update({"level_name":"College","load_url":"forms_college/","user_object":user_object})
                    return render(request, "new_include/user_new.html",context=context)
                return render(request, "new_include/user_new.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t college_users_college \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/user_new.html",context=context)

    def post(self,request):
        response_dict = {}
        try:
            response_dict = add_edit_delete_user(request)
            ielite_logger.info("user_management \t college_users_college \t post method to store college level user data")
            # send_mail('User Creation Conformation', "Dear user,\n\n Congratulations your account is created with, \n user id: "+login_id +"\n\n Thank you\n",settings.EMAIL_HOST_USER,[email_id], fail_silently=False)
            return HttpResponse(json.dumps(response_dict),content_type='application/javascript',status=200)
        except Exception as e:
            ielite_except_logger.critical('user_management \t college_users_college \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)
        return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

def forms_college(request):
        context = {}
        try:
            # import ipdb;ipdb.set_trace()
            ct_obj = ContentType.objects
            get_data = request.GET
            response_dict = {}
            ielite_logger.info("user_management \t forms_college \t get method to load college level user page")
            if get_data.get("status") == "get_user":
                user_id = request.GET.get("ids")
                user_object = UserDetails.objects.select_related().get(pk = user_id)
                response_dict = edit_all_user(request,user_object)
                response_dict.update({"university":list(user_object.user_userrolemaps.get(permanent_role = True).role_manager_id.content_type.get_all_objects_for_this_type().values_list("pk","college_name")),})
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                # pdb.set_trace()
                # values = request.user.users.user_userrolemaps.get(permanent_role = True)
                ct_obj = ContentType.objects
                # rolelist = list(request.user.users.roles.all().values_list('content_type_id',flat=True))
                # role_m_id  = values.role_manager_id.content_type_id
                group_pk = request.user.groups.get().pk
                role_m_id  = RoleManager.objects.get(group_ptr__pk = group_pk).content_type_id
                ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
                ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                # c_objects = ConfigMaster.objects.all()
                if ctu_pk == role_m_id:
                    # pdb.set_trace()
                    z_roles = ""
                    c_roles = ""
                    u_roles = ""
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    for each in role_obj:
                        if int(each) == ct_obj.get(model = "universitydetails").pk:
                            u_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "zonedetails").pk:
                            z_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "collegedetails").pk:
                            c_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                    # response_dict.update({'u_role':})

                    zone_object = CollegeDetails.objects.all()
                    context.update({"GENDER_CHOICES":UserDetails.GENDER_CHOICES,"PROFESSION_TITLE":PROFESSION_TITLE,"roles_privilege":"c_r_p","add_edit_url":"college_users_college",
                        "edit_instance":"college_users_college","zone_object":zone_object,
                        "user_object":user_object,"u_role_object":c_roles,"z_role_object":z_roles,
                        "c_role_object":c_roles})
                    return render(request, "new_include/forms/user_form.html",context=context)
                
                elif ctz_pk == role_m_id:
                    #pdb.set_trace()
                    z_roles = ""
                    c_roles = ""
                    u_roles = ""
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True,object_id = request.user.users.object_id)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    for each in role_obj:
                        # if int(each) == ct_obj.get(model = "universitydetails").pk:
                        #     u_roles=val.filter(content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "zonedetails").pk:
                            z_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "collegedetails").pk:
                            c_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                    # response_dict.update({'u_role':})
                    zone_object = CollegeDetails.objects.filter(pk = request.user.users.object_id)
                    context.update({"GENDER_CHOICES":UserDetails.GENDER_CHOICES,"PROFESSION_TITLE":PROFESSION_TITLE,"add_edit_url":"college_users_college","edit_instance":"college_users_college","zone_object":zone_object,"user_object":user_object,"u_role_object":u_roles,"z_role_object":z_roles,"c_role_object":c_roles})
                    return render(request, "new_include/forms/user_form.html",context=context)
                else:
                    # pdb.set_trace()
                    z_roles = ""
                    c_roles = ""
                    u_roles = ""
                    ct_obj = ContentType.objects
                    ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("group_ptr__pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__group_ptr__in = zone_user_list,permanent_role = True).values_list("user_details_id",flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list,status = True,object_id = request.user.users.object_id)
                    val = RoleManager.objects.select_related()
                    role_obj = val.all().values_list("content_type_id",flat=True).distinct()
                    for each in role_obj:
                        # if int(each) == ct_obj.get(model = "universitydetails").pk:
                        #     u_roles=val.filter(content_type_id__in = [int(each)])
                        # if int(each) == ct_obj.get(model = "zonedetails").pk:
                        #     z_roles=val.filter(content_type_id__in = [int(each)])
                        if int(each) == ct_obj.get(model = "collegedetails").pk:
                            c_roles=val.filter(is_active = True,status = True,content_type_id__in = [int(each)])
                    # response_dict.update({'u_role':})
                    zone_object = CollegeDetails.objects.filter(pk = request.user.users.object_id)
                    context.update({"GENDER_CHOICES":UserDetails.GENDER_CHOICES,"PROFESSION_TITLE":PROFESSION_TITLE,"add_edit_url":"college_users_college",
                        "edit_instance":"college_users_college","zone_object":zone_object,"user_object":user_object,"u_role_object":u_roles,"z_role_object":z_roles,"c_role_object":c_roles})
                    return render(request, "c_user.html",context=context)
                return render(request, "new_include/forms/user_form.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t forms_college \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/forms/user_form.html",context=context)

class college_privilege_roles(View):
    def get(self,request):
        #pdb.set_trace()
        context = {}
        response_dict = {}
        try:
            ielite_logger.info("user_management \t college_privilege_roles \t get method to load college level privilege roles page")
            get_data = request.GET
            if get_data.get("status") == "get_roles":
                
                rm_obj = RoleManager.objects.get(group_ptr__pk = get_data.get("get_id"))
                per_list = list(rm_obj.permissions.values_list("content_type_id","codename"))
                response_dict.update({"per_list" : per_list,"name":str(rm_obj.name),
                    "role_level":rm_obj.content_type.name,"role_id":rm_obj.content_type.pk})
                
                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                ct_obj = ContentType.objects
                rolelist = list(request.user.users.roles.all().values_list('content_type_id',flat=True))
                ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
                ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
                c_objects = ConfigMaster.objects.all()
                user_role_list = list(request.user.users.user_userrolemaps.all().values_list("role_manager_id",flat = True))
                if ctu_pk in rolelist:
                    
                    ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                    zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("pk",flat = True))
                    user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list).values_list("user_details_id",
                        flat = True))
                    user_object = UserDetails.objects.filter(pk__in = user_list)
                    role_object = RoleManager.objects.filter(content_type = ct_id,status = True).exclude(group_ptr__pk__in = user_role_list)
                    coll_object = CollegeDetails.objects.all()
                    zone_object = ZoneDetails.objects.all()
                    c_objects = ConfigMaster.objects.all()
                elif ctz_pk in rolelist:
                    #pdb.set_trace()
                    user_list = list(request.user.userdetails.user_role_map.filter(priority=1).values_list("user_details_id",
                        flat = True))
                    ct_obj_list = request.user.userdetails.roles.select_related().values_list("object_id",flat = True)
                    ct_id = ct_obj.get(app_label ='user_management',model = "collegedetails").pk
                    user_object = UserDetails.objects.filter(pk__in = user_list)
                    role_object = RoleManager.objects.filter(content_type = ct_id,status = True,object_id__in = ct_obj_list).exclude(group_ptr__pk__in = user_role_list)
                    
                    zone_object = ZoneDetails.objects.filter(pk = ct_obj_list)
                    coll_object = CollegeDetails.objects.filter(zone = zone_object[0].pk)
                    c_objects = ConfigMaster.objects.all()
                else:
                    #pdb.set_trace()
                    user_list = list(request.user.userdetails.user_role_map.filter(priority=1).values_list("user_details_id",
                        flat = True))
                    ct_obj_list = request.user.userdetails.roles.select_related().values_list("object_id",flat = True)
                    ct_id = ct_obj.get(app_label ='user_management',model = "collegedetails").pk
                    user_object = UserDetails.objects.filter(pk__in = user_list)
                    role_object = RoleManager.objects.filter(content_type = ct_id,status = True,object_id__in = ct_obj_list).exclude(group_ptr__pk__in = user_role_list)

                    coll_instance = CollegeDetails.objects.get(pk = ct_obj_list)
                    coll_object = CollegeDetails.objects.filter(pk = ct_obj_list)
                    zone_object = ZoneDetails.objects.filter(pk = coll_instance.pk)
                context.update({"role_form_url":"college_roles_formsk",
                    "user_object":user_object,"c_objects":c_objects,
                    "role_object":role_object,"coll_object":coll_object,"zone_object":zone_object})
                return render(request, "new_include/role_privileges.html",context=context)
        except Exception as e:
            ielite_except_logger.critical('user_management \t college_privilege_roles \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/role_privileges.html",context=context)


    def post(self,request):
        # pdb.set_trace()
        response_dict = {}
        temp_list = [[],[],[],[],[],[],[],[]]
        view_list = []
        add_list = []
        edit_list = []
        delete_list = []
        get_view_list = []
        get_add_list = []
        get_edit_list = []
        get_delete_list = []
        post_data = request.POST
        try:
            ielite_logger.info("user_management \t college_privilege_roles \t post method to store college level privilege roles data")
            if post_data.get('role_status') == 'add':
                # pdb.set_trace()
                datas = request.POST
                role_name = post_data.get("role_name")
                rm_obj = RoleManager.objects.create(
                    content_type = ContentType.objects.get(app_label ='college_management',model = "collegedetails"),
                    name = role_name,
                    created_by = 1,
                )
                # rm_obj.save()
                #pdb.set_trace()
                view_list.extend(datas.getlist('view') if datas.getlist('view') else [])
                add_list.extend(datas.getlist('add') if datas.getlist('add') else [])
                edit_list.extend(datas.getlist('edit') if datas.getlist('edit') else [] )
                delete_list.extend(datas.getlist('delete') if datas.getlist('delete') else [])

                main_list = {0:add_list,1:edit_list,2:delete_list,3:view_list}
                p_obj = Permission.objects
                for each in main_list:
                    for view_id in main_list[each]:
                        view_obj  = p_obj.filter(content_type_id = int(view_id))[each]
                        rm_obj.permissions.add(view_obj)

                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
            else:
                # pdb.set_trace()
                datas = request.POST
                role_name = datas.get("role_name")
                edit_id = int(datas.get('u_r_edit_id'))
                rm_obj = RoleManager.objects.get(group_ptr__pk = edit_id)
                rm_obj.name = role_name
                rm_obj.save()
                view_list.extend(datas.getlist('view') if datas.getlist('view') else [])
                add_list.extend(datas.getlist('add') if datas.getlist('add') else [])
                edit_list.extend(datas.getlist('edit') if datas.getlist('edit') else [] )
                delete_list.extend(datas.getlist('delete') if datas.getlist('delete') else [])

                rm_obj = RoleManager.objects.get(group_ptr__pk = edit_id)
                get_view_list.extend(list(rm_obj.permissions.filter(codename__contains = "view").values_list("content_type_id",flat=True)))
                get_add_list.extend(list(rm_obj.permissions.filter(codename__contains = "add").values_list("content_type_id",flat=True)))
                get_edit_list.extend(list(rm_obj.permissions.filter(codename__contains = "change").values_list("content_type_id",flat=True)))
                get_delete_list.extend(list(rm_obj.permissions.filter(codename__contains = "delete").values_list("content_type_id",flat=True)))

                get_list = [get_add_list,get_edit_list,get_delete_list,get_view_list]
                main_list = {0:add_list,1:edit_list,2:delete_list,3:view_list}
                p_obj = Permission.objects
                for each in main_list:
                    if main_list[each]:
                        adding_list = [item for item in main_list[each] if int(item) not in get_list[each]]
                        if adding_list:
                            for view_id in adding_list:
                                view_obj  = p_obj.filter(content_type_id = view_id)[each]
                                rm_obj.permissions.add(view_obj)
                    if get_list[each]:
                        remove_list = [item for item in get_list[each] if str(item) not in main_list[each]]
                        if remove_list:
                            for view_id in remove_list:
                                view_obj  = p_obj.filter(content_type_id = view_id)[each]
                                rm_obj.permissions.remove(view_obj)

                return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)

        except Exception as e:
            ielite_except_logger.critical('user_management \t college_privilege_roles \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

def college_roles_forms(request):    
    # pdb.set_trace()
    context = {}
    response_dict = {}
    try:
        ielite_logger.info("user_management \t college_roles_forms \t method to load college level privilege roles form page")
        get_data = request.GET
        if get_data.get("status") == "get_roles":
            
            rm_obj = RoleManager.objects.get(group_ptr__pk = get_data.get("get_id"))
            per_list = list(rm_obj.permissions.values_list("content_type_id","codename"))
            response_dict.update({"per_list" : per_list,"name":str(rm_obj.name),
                "role_level":rm_obj.content_type.name,"role_id":rm_obj.content_type.pk})
            
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)
        else:
            ct_obj = ContentType.objects
            rolelist = list(request.user.users.roles.all().values_list('content_type_id',flat=True))
            ctu_pk = ct_obj.get(app_label='college_management', model = "universitydetails").pk
            ctz_pk = ct_obj.get(app_label='college_management',model = "zonedetails").pk
            c_objects = ConfigMaster.objects.all()
            user_role_list = list(request.user.users.user_userrolemaps.all().values_list("role_manager_id",flat = True))
            if ctu_pk in rolelist:
                
                ct_id = ct_obj.get(app_label='college_management',model = "collegedetails").pk
                zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("pk",flat = True))
                user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list).values_list("user_details_id",
                    flat = True))
                user_object = UserDetails.objects.filter(pk__in = user_list)
                role_object = RoleManager.objects.filter(content_type = ct_id,status = True).exclude(group_ptr__pk__in = user_role_list)
                coll_object = CollegeDetails.objects.all()
                zone_object = ZoneDetails.objects.all()
                c_objects = ConfigMaster.objects.all()
            elif ctz_pk in rolelist:
                #pdb.set_trace()
                user_list = list(request.user.userdetails.user_role_map.filter(priority=1).values_list("user_details_id",
                    flat = True))
                ct_obj_list = request.user.userdetails.roles.select_related().values_list("object_id",flat = True)
                ct_id = ct_obj.get(app_label ='user_management',model = "collegedetails").pk
                user_object = UserDetails.objects.filter(pk__in = user_list)
                role_object = RoleManager.objects.filter(content_type = ct_id,status = True,object_id__in = ct_obj_list).exclude(group_ptr__pk__in = user_role_list)
                
                zone_object = ZoneDetails.objects.filter(pk = ct_obj_list)
                coll_object = CollegeDetails.objects.filter(zone = zone_object[0].pk)
                c_objects = ConfigMaster.objects.all()
            else:
                #pdb.set_trace()
                user_list = list(request.user.userdetails.user_role_map.filter(priority=1).values_list("user_details_id",
                    flat = True))
                ct_obj_list = request.user.userdetails.roles.select_related().values_list("object_id",flat = True)
                ct_id = ct_obj.get(app_label ='user_management',model = "collegedetails").pk
                user_object = UserDetails.objects.filter(pk__in = user_list)
                role_object = RoleManager.objects.filter(content_type = ct_id,status = True,object_id__in = ct_obj_list).exclude(group_ptr__pk__in = user_role_list)

                coll_instance = CollegeDetails.objects.get(pk = ct_obj_list)
                coll_object = CollegeDetails.objects.filter(pk = ct_obj_list)
                zone_object = ZoneDetails.objects.filter(pk = coll_instance.pk)
            context.update({"roles_privilege":"c_r_p","user_object":user_object,
                "c_objects":c_objects,
                "role_object":role_object,"coll_object":coll_object,"zone_object":zone_object})

            return render(request, "new_include/forms/roles_privilege_form.html",context=context)
    except Exception as e:
        ielite_except_logger.critical('user_management \t college_privilege_roles \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return render(request, "new_include/forms/roles_privilege_form.html",context=context)


##****** dept to user map ******##
from django.db.models import Count
class dept_role_map(View):
    def get(self,request):
        if request.GET.get("edit_id"):
            # pdb.set_trace()
            response_dict = {}
            edit_data=RoleDepartmentMap.objects.filter(status = True,
                degree_branch = request.GET.get("edit_id"),
                user_role = request.GET.get("user_pk") ).values(
                "degree_branch__degree_branch_map_name",
                "degree_branch__degree_branch_map_id",
                "user_role__role_manager_id__pk",
                "user_role__user_details_id",
                "user_role__user_details_id__first_name",
                "user_role__user_details_id__last_name",
                "user_role__object_id",
                )

            response_dict.update({"edit_data": list(edit_data)})
            return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

        context = {}
        # pdb.set_trace()
        role_dept_data = RoleDepartmentMap.objects.filter(status = True)
        context.update({"role_dept_obj": role_dept_data.values(
            "degree_branch__degree_branch_map_name",
            "user_role__role_manager_id__name",
            "degree_branch__degree_branch_map_id",
            ).annotate(Count("user_role"))
        })
        return render(request, "new_include/dept_to_role_map.html",context=context)

    def post(self,request):
        response_dict = {}
        # pdb.set_trace()
        user_list = request.POST.getlist("dept_user[]")
        dept = request.POST.get("dept")
        role_id = request.POST.get("dept_role_id")
        degree_brench_obj =DegreeBranchMapping.objects.get(pk = dept)
        RoleDepartmentMap.objects.filter(degree_branch = degree_brench_obj).update(status = False)
        for each in user_list:
            user_role_obj = UserRoleMap.objects.get(user_details_id = each,role_manager_id = role_id)
            role_dept_map,created = RoleDepartmentMap.objects.get_or_create(
            user_role = user_role_obj,
            degree_branch = degree_brench_obj,
            defaults={"created_by" : request.user.pk,'status':True}
            )
            if created:
                pass
            else:
                role_dept_map.degree_branch = degree_brench_obj
                role_dept_map.user_role = user_role_obj
                role_dept_map.status = True
                role_dept_map.save()
        return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)


def dept_to_role_form(request):
    context = {}
    context.update({"college":CollegeDetails.objects.filter(status = True),
        "role":RoleManager.objects.filter(status = True)})
    return render(request, "new_include/forms/dept_role_map_form.html",context=context)

def get_user_from_role(request):
    response_dict = {}
    # pdb.set_trace()
    role_pk = request.GET.get("role_pk")
    coll_id = request.GET.get("coll_pk")
    user_data = UserDetails.get_user_by_role(role_pk,coll_id).values("pk","first_name","last_name")
    response_dict.update({"user_data":list(user_data)})
    return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

def get_dept_by_coll(request):
    response_dict = {}
    coll_pk = request.GET.get("coll_pk")
    dept_data = CollegeProgrammeMapping.objects.filter(college_id = coll_pk).values(
        "programme_id__degree_branch_map_id__degree_branch_map_name",
        "programme_id__degree_branch_map_id__pk")

    response_dict.update({"dept_data":list(dept_data)})
    return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)

def delete_user_dept(request):
    response_dict = {}
    # pdb.set_trace()
    RoleDepartmentMap.objects.filter(degree_branch = request.POST.get("delete_id")).update(status = False)
    return HttpResponse(json.dumps(response_dict), 
                    content_type='application/javascript',
                    status=200)
##****** End ******##

#################* End *#################

class Report(ErrorMessage,View):
    def get(self, request):
        context ={}
        context.update({"content":content.contents["report_management"]})
        return render(request, "reports.html", context=context)

class get_rolemanager(ErrorMessage,View): 
    def get(self,request): 
        object_dict={}
        try:
            role_manager_id = request.GET.get('role_manager_id','') 
            role_manage_name=RoleManager.objects.filter(pk= int(role_manager_id))
            content_type_id=role_manage_name.values_list('content_type')
            content_type_model=ContentType.objects.get(pk=content_type_id[0][0])
            model_object=content_type_model.model_class()
            result=model_object().__class__.objects.filter(status=True)
            for data in result:
                object_dict[str(data.pk)] =[v for x,v in (data.get_object_name(data.pk)[0]).items()][0]
        except Exception as e:
            ielite_except_logger.critical('user_management \t get_rolemanager \t '+str(e) +'\n'+ str(traceback.format_exc()))
        return HttpResponse(json.dumps(object_dict), content_type="application/json")


class GetBuildNo(TemplateView):

    template_name = 'new_include/build_number.html'
    
    def get_context_data(self, *args, **kwargs):
        context = super(GetBuildNo, self).get_context_data(*args, **kwargs)
        context['build_data'] = get_build_number()
        return context

class user_group(ErrorMessage,View):
    
    def get(self,request):
        context = {}
        try:
            # pdb.set_trace()
            # ct_obj = ContentType.objects
            # ct_id = ct_obj.get(app_label='college_management', model = "universitydetails").pk
            # zone_user_list =list(RoleManager.objects.filter(content_type_id = ct_id).values_list("pk",flat = True))
            # user_list = list(UserRoleMap.objects.filter(role_manager_id__in = zone_user_list).values_list("user_details_id",flat = True))
            # user_object = UserDetails.objects.filter(pk__in = user_list)
            
            context.update({"group_key":"UserGroup"})
            context.update({"content":content.contents["college"]})
            ielite_logger.info("user_management \t college_usermanagements \t get method to load college level user page")
            return render(request, "new_include/user_group.html",context=context)
        except Exception as e:
            pass
            ielite_except_logger.critical('user_management \t college_usermanagements \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/user_group.html",context=context)



## ------ this function is for form page of user bulkupload -----------##############

def user_bulkupload(request):
    context={}
    try:
        user_detail  = UserDetails.objects.filter(status=True)
        return render(request,'new_include/forms/user_bulkupload.html',context=context)
    except Exception as e:
        ielite_except_logger.critical(str(e) +'\n'+ str(traceback.format_exc()))
  
        return render(request,'new_include/forms/user_bulkupload.html',context=context)

from user_management import config, bulk_upload
from xlsxwriter.utility import xl_rowcol_to_cell

def programme_definition_templates(request):
    # import ipdb;ipdb.set_trace()
    module = request.GET.get('module_name')
    file_path = bulk_upload.create_filepath('user_management', 'user_info')
    df = pd.DataFrame()
    writer = pd.ExcelWriter(file_path, engine='xlsxwriter')
    workbook  = writer.book
    worksheet = workbook.add_worksheet('user_details')
    hidden_worksheet=workbook.add_worksheet('Dropdowns')
    worksheet.set_row(0,45)
    headers = column_headers(module)
    unlocked = workbook.add_format()
    unlocked.set_locked(False)
    header_format = workbook.add_format(bulk_upload.excel_formats()[0])
    mandatory_format = workbook.add_format(bulk_upload.excel_formats()[2])
    count=0
    mandatory_field_check = mandatory_fields(module)
    for i in headers: 
        if  isinstance(i, dict):
            for key, val in i.items():
                worksheet.write(0, count, key, mandatory_format)
                dropdown_range  = bulk_upload.hidden_column_dropdown(hidden_worksheet, val, headers.index(i), 'Dropdowns')
                bulk_upload.data_validation(count, worksheet, None, dropdown_range, key)
        else:
            if i in mandatory_field_check:
                worksheet.write(0, count, i, mandatory_format)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)

            else:
                worksheet.write(0, count, i, header_format)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
        count = count+1
    hidden_worksheet.hide()
    worksheet.protect()
    worksheet.set_column('A:M',20, unlocked)
    writer.save()
    workbook.close()
    return bulk_upload.download_template(file_path)

##### department bulk upload xl sheet download code start :added by krishna ##############
def department_bulkupload_templates(request):
    # import ipdb;ipdb.set_trace()
    module = request.GET.get('module_name')
    file_path = bulk_upload.create_filepath('user_management', 'department_info')
    df = pd.DataFrame()
    writer = pd.ExcelWriter(file_path, engine='xlsxwriter')
    workbook  = writer.book
    worksheet = workbook.add_worksheet('Department_details')
    hidden_worksheet=workbook.add_worksheet('Dropdowns')
    worksheet.set_row(0,45)
    headers = dip_column_headers(module)
    unlocked = workbook.add_format()
    unlocked.set_locked(False)
    header_format = workbook.add_format(bulk_upload.excel_formats()[0])
    mandatory_format = workbook.add_format(bulk_upload.excel_formats()[2])
    count=0
    mandatory_field_check = dip_mandatory_fields(module)
    for i in headers:
        if  isinstance(i, dict):
            for key, val in i.items():
                worksheet.write(0, count, key, mandatory_format)
                dropdown_range  = bulk_upload.hidden_column_dropdown(hidden_worksheet, val, headers.index(i), 'Dropdowns')
                bulk_upload.data_validation(count, worksheet, None, dropdown_range, key)
        else:
            if i in mandatory_field_check:
                worksheet.write(0, count, i, mandatory_format)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
            else:
                worksheet.write(0, count, i, header_format)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
        count = count+1
    hidden_worksheet.hide()
    worksheet.protect()
    worksheet.set_column('A:M',20, unlocked)
    writer.save()
    workbook.close()
    return bulk_upload.download_template(file_path)

##### Academic Session bulk upload xl sheet download code start :added by krishna ##############
def AcademicSessionBulkuploadTemplates(request):
    module = request.GET.get('module_name')
    xl_file_path = bulk_upload.create_filepath('user_management','session_info')
    xl_writer = pd.ExcelWriter(xl_file_path,engine='xlsxwriter')
    xl_workbook = xl_writer.book
    worksheet = xl_workbook.add_worksheet('Academic_Session_details')
    hidden_worksheet = xl_workbook.add_worksheet('Dropdown')
    worksheet.set_row(0,45)
    file_headers = session_column_headers(module)
    unlocked = xl_workbook.add_format()
    unlocked.set_locked(False)
    xl_header_format = xl_workbook.add_format(bulk_upload.excel_formats()[0])
    mandatory_format_xl = xl_workbook.add_format(bulk_upload.excel_formats()[2])
    count = 0
    xl_mandatory_field_check = session_mandatory_fields(module)
    for i in file_headers:
        if isinstance(i, dict):
            for key, val in i.items():
                worksheet.write(0, count, key, mandatory_format_xl)
                dropdown_range = bulk_upload.hidden_column_dropdown(hidden_worksheet, val, file_headers.index(i), 'Dropdown')
                bulk_upload.data_validation(count, worksheet, None, dropdown_range, key)
        else:
            if i in xl_mandatory_field_check:
                worksheet.write(0, count, i, mandatory_format_xl)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
            else:
                worksheet.write(0, count, i, xl_header_format)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
        count = count+1
    hidden_worksheet.hide()
    worksheet.protect()
    worksheet.set_column('A:M',20, unlocked)
    xl_writer.save()
    xl_workbook.close()
    return  bulk_upload.download_template(xl_file_path)


##### Course bulk upload xl sheet download code start :added by krishna ##############
def CourseBulkuploadTemplates(request):
    module = request.GET.get('module_name')
    xl_file_path = bulk_upload.create_filepath('user_management','Course_info')
    xl_writer = pd.ExcelWriter(xl_file_path,engine='xlsxwriter')
    xl_workbook = xl_writer.book
    worksheet = xl_workbook.add_worksheet('Course_details')
    hidden_worksheet = xl_workbook.add_worksheet('Dropdown')
    worksheet.set_row(0,45)
    file_headers = course_coloumn_headers(module)
    unlocked = xl_workbook.add_format()
    unlocked.set_locked(False)
    xl_header_format = xl_workbook.add_format(bulk_upload.excel_formats()[0])
    mandatory_format_xl = xl_workbook.add_format(bulk_upload.excel_formats()[2])
    count = 0
    xl_mandatory_field_check = course_mandatory_fields(module)
    for i in file_headers:
        if isinstance(i, dict):
            for key, val in i.items():
                worksheet.write(0, count, key, mandatory_format_xl)
                dropdown_range = bulk_upload.hidden_column_dropdown(hidden_worksheet, val, file_headers.index(i), 'Dropdown')
                bulk_upload.data_validation(count, worksheet, None, dropdown_range, key)
        else:
            if i in xl_mandatory_field_check:
                worksheet.write(0, count, i, mandatory_format_xl)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
            else:
                worksheet.write(0, count, i, xl_header_format)
                data = bulk_upload.data_attributes(i, programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
        count = count+1
    hidden_worksheet.hide()
    worksheet.protect()
    worksheet.set_column('A:M',20, unlocked)
    xl_writer.save()
    xl_workbook.close()
    return  bulk_upload.download_template(xl_file_path)

def check_mandatory(df, mandatory_fields, module, i):
    field_check=[]
    for field in mandatory_fields(module):
        if df[field][i]=='':
            field_check.append('true')
        else:
            field_check.append('false')
    return field_check

def file_download(request):
    file_path = request.GET['file_name']
    with open(file_path,'rb') as  file_obj:
        response=HttpResponse(FileWrapper(file_obj),content_type='application/xls')
        filename = os.path.split(file_path)[-1]
        response['Content-Disposition'] = "attachment; filename=%s"%filename
        response['Content-Length']  = os.path.getsize(file_path)
    return response




import pandas as pd
from django.http import JsonResponse
import time
import re
from time import sleep
class UserBulUpload(APIView):
    # @csrf_exempt
    def post(self, request):

        try:
            http_protocol = 'http://'
            if request.is_secure():
                http_protocol = 'https://'
            host = http_protocol+request.META['HTTP_HOST']
            c = Crypto()
            
            prog_files= request.FILES.get('file')
            module = request.GET.get('module_name')
            validate_count = request.GET.get('validate')
            '''
            "sheetname" has renamed to "sheet_name" because of it seems that this "sheet_name" could be language dependent
            '''
            df = pd.read_excel(prog_files, header=0, sheet_name='user_details')
            df2 = pd.DataFrame(columns=['User Id', 'Role', 'User First Name', 'User Email Id', 'User Last Name', 'Address1', 'Address2', 'Phone Number', 'Qualification', 'Designation', 'Experience', 'Specialization', 'Error Message'])
            # print(df,'excel data reading.........')
            df = df.replace(np.nan, '', regex=True)
            # error_user_count = 0
            exisitng_users_count = 0
            new_user_count = 0
            empty_fields_count = 0
            no_spaces_userId_count = 0

            conditon = 'true';
            for i in range(0, df['User Id'].count()):
                mandatory_check = check_mandatory(df, mandatory_fields, 'CollegeUsers', i)

                if (conditon in mandatory_check):
                    error_msg = "Mandatory Fields are Empty!"
                    empty_fields_count += 1
                    user = df.iloc[[i]]
                    df2 = df2.append(user, sort = False)
                    df2.loc[i, "Error Message"] = error_msg
                else:
                    tempUser = str(df.iloc[i][0])
                    res = bool(re.search(r"\s", tempUser))
                    if (res):
                        error_msg = "There should be No Spaces within the User Id field!"
                        no_spaces_userId_count += 1
                        user = df.iloc[[i]]
                        df2 = df2.append(user, sort = False)
                        df2.loc[i, "Error Message"] = error_msg
                    else:
                        random_pwd = random_password()
                        obj =User.objects.filter(username=df['User Id'][i])
                        if not obj.exists():
                            new_user_count += 1
                            new_user = User.objects.create(username=str(df['User Id'][i]),email=str(df['User Email Id'][i]))
                            new_user.set_password(random_pwd)
                            new_user.save()
                            StudentTmpPwd.objects.create(student_temp_pwd=new_user, code=random_pwd,created_by=1)

                            user_data = User.objects.get(username=df['User Id'][i])
                            user_role = RoleManager.objects.get(name=df['Role'][i])
                            user_role_map = new_user.groups.add(user_role)
                            # user_inst = User.objects.get(username=df['Student Login Id'][i])
                            
                            # if df['Group Name'][i] is not '':
                            #     # group_instanc = UserGroup.objects.get(group_name=df['Group Name'][i])
                            #     user_group=UserGroup.objects.create(group_name = df['Group Name'][0],user=user_inst,)
                            #     # user_group.save()
                            # user_group=None
                                        # pass
                                        # user_group = UserGroup.objects.filter(user=user_objs,group_name =df['Group Name'][i] )
                                            # user_group.save()

                            user_detail = UserDetails(user=user_data,
                                                      email_id=str(df['User Email Id'][i]),
                                                      first_name=str(df['User First Name'][i]),
                                                      last_name=str(df['User Last Name'][i]),
                                                      phone_no=str(df['Phone Number'][i]),
                                                      address1=str(df['Address1'][i]),
                                                      created_by=1,
                                                      device_user_id='123456',
                                                      object_id=1,
                                                      title=1,
                                                      gender=1)
                            user_detail.save()

                            user_role = UserRoleMap(user_details_id=user_detail,
                                                    role_manager_id=user_role,
                                                    # user_group_id=user_group,
                                                    permanent_role=True,
                                                    priority_role=True,
                                                    is_active=True,
                                                    object_id='123123',
                                                    # start_time='2020-04-20 06:00:00.000000-08:00',
                                                    # end_time='2030-04-20 06:00:00.000000-08:00',
                                                    # user_group_id=user_group,
                                                    created_by=1)

                            user_role.save()
                        else:
                            error_msg = "This User already Exists!"
                            exisitng_users_count += 1
                            user = df.iloc[[i]]
                            df2 = df2.append(user, sort = False)
                            df2.loc[i, "Error Message"] = error_msg
                            # error_user_count += 1

            now = datetime.now()
            time_now = now.strftime("%d-%m-%Y-%H-%M")


            main_folder_path = "media/error_reports"
            abs_main_file_path = os.path.join(settings.BASE_DIR, main_folder_path)

            if not os.path.exists(abs_main_file_path):
                os.mkdir(abs_main_file_path)

            user_error_report_path = "/user_bulk_upload"
            abs_folder_path = abs_main_file_path + user_error_report_path

            if not os.path.exists(abs_folder_path):
                os.mkdir(abs_folder_path)

            user_file_name = "/" + time_now + "___" + str(prog_files.name)

            abs_media_path = abs_folder_path + user_file_name        

            media_path = main_folder_path + user_error_report_path + user_file_name
            file_path = host + "/" + media_path



            df2.to_excel(abs_media_path, index=False)

            # return JsonResponse({"file_path":file_path, "msg": 'data uploaded successfully',"prog_def_count": str(df['User Id'].count()),"invalid_data": (int(df['User Id'].count() - int(count)))})
            return JsonResponse({"file_path":file_path, "msg": 'data uploaded successfully',"prog_def_count": str(df['User Id'].count()), 
                "new_user_count": str(new_user_count), "exisitng_users_count": str(exisitng_users_count), 
                "empty_fields_count": str(empty_fields_count), "no_spaces_userId_count": str(no_spaces_userId_count)})
            if request.GET.get('validate') =='true':
                return JsonResponse({"file_path":file_path, "prog_def_count": str(df['User Id'].count()),
                    "invalid_data": str(count)})
        except Exception as e:
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return JsonResponse({"error":"invalid_file"})


class DepartmentBulUpload(APIView):
    # @csrf_exempt
    def post(self, request):
        response_dict = {"status": True, "message": ""}
        try:
            prog_files = request.FILES.get('file')
            df = pd.read_excel(prog_files, header=0, sheet_name='Department_details')
            df = df.replace(np.nan, '', regex=True)
            count = 0
            for i in range(0, df['Department Id'].count()):
                obj = Departments.objects.filter(department_id=df['Department Id'][i])
                if not obj.exists():
                    count += 1
                    # import ipdb; ipdb.set_trace()
                    new_dip = Departments.objects.create(department_id=str(df['Department Id'][i]),department_name=str(df['Department Name'][i]),created_by=1)
                    new_dip.save()
            return JsonResponse({"msg": 'Department data updated successfully', "dep_prog_def_count": str(df['Department Id'].count()),
                                 "dep_invalid_data": (int(df['Department Id'].count() - int(count)))})
            if request.GET.get('validate') == 'true':
                current_path = os.getcwd()
                op_path = current_path + '/user_management/excel_templates/' + str(prog_file)
                df.to_excel(op_path)
                return JsonResponse({"dep_file_path": op_path, "dep_prog_def_count": str(df['Department Id'].count()),
                                     "dep_invalid_data": str(count)})
        except Exception as e:
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            response_dict['status'] = False
            response_dict['message'] = 'Invalid file'
        return Response(response_dict)


class SessionBulUpload(APIView):
    def post(self, request):
        """
            API to upload Bulk AcademySession details
        """
        response_dict = {"status": True, "message": "saved session details"}
        try:
            session_files = request.FILES.get('file')
            df = pd.read_excel(session_files, header=0, sheet_name='Academic_Session_details')
            df = df.replace(np.nan, '', regex=True)
            count = 0
            for i in range(0, df['Session Id'].count()):
                obj = AcademySession.objects.filter(session_id=df['Session Id'][i])
                if not obj.exists():
                    count += 1
                    new_session = AcademySession.objects.create(session_id=str(df['Session Id'][i]), session_name=str(df['Session Name'][i]),session_start_date=str(df['Session Start Date'][i]),
                                                                session_end_date=str(df['Session End Date'][i]),session_status=True,created_by=1)
                    new_session.save()
            return JsonResponse({"msg": 'AcademySession data uploaded successfully', "prog_ses_count": str(df['Session Id'].count()),
                                     "ses_invalid_data": (int(df['Session Id'].count() - int(count)))})
            if request.GET.get('validate') == 'true':
                current_path = os.getcwd()
                op_path = current_path + '/user_management/excel_templates/' + str(prog_file)
                df.to_excel(op_path)
                return JsonResponse({"ses_file_path": op_path, "prog_ses_count": str(df['Session Id'].count()),
                                     "ses_invalid_data": str(count)})

                # else:
                #     response_dict['status'] = False
                #     response_dict['data'] = {}
                #     response_dict['message'] = 'AcademySession already created'
        except Exception as e:
            ielite_except_logger.critical("AcademySession save session details: (%s)" % str(e))
            response_dict['status'] = False
            response_dict['data'] = {}
            response_dict['message'] = 'no AcademySession data'
        return Response(response_dict)


class CourseBulUpload(APIView):
    def post(self,request):
        response_dict = {"status":True , "message":"saved course details"}
        try:
            course_files = request.FILES.get('file')
            dp = pd.read_excel(course_files, header=0 , sheet_name='Course_details')
            df = dp.replace(np.nan, '',regex=True)

            count=0
            for i in range(0,df['Course Name'].count()):

                Exam_Exam_code = random.randint(1000, 9999)
                if df['Department Id'][i] is not '':
                    d_obj = Departments.objects.get(department_id = str(df['Department Id'][i]))
                else:
                    d_obj = None
                if df['Session Id'][i] is not '':
                    s_obj = AcademySession.objects.get(session_id = str(df['Session Id'][i]))
                else:
                    s_obj = None
                obj = ExamSeries.objects.filter(exam_series_name=str(df['Course Name'][i]),under_department=d_obj, under_session=s_obj)
                if obj.exists():
                    continue
                else:
                    count += 1
                    new_course = ExamSeries.objects.create(exam_series_id=Exam_Exam_code,
                                                           exam_schedule_id=Exam_Exam_code,
                                                           exam_series_name=str(df['Course Name'][i]), created_by=1,
                                                           under_department=d_obj, under_session=s_obj)
                    new_course.save()
            return JsonResponse({"msg": 'Course data uploaded successfully',
                                     "prog_ses_count": str(df['Course Name'].count()),
                                     "ses_invalid_data": (int(df['Course Name'].count() - int(count)))})
            if request.GET.get('validate') == 'true':
                current_path = os.getcwd()
                op_path = current_path + '/user_management/excel_templates/' + str(prog_file)
                df.to_excel(op_path)
                return JsonResponse({"ses_file_path": op_path, "prog_ses_count": str(df['Course Name'].count()),
                                     "ses_invalid_data": str(count)})
        except Exception as e:
            ielite_except_logger.critical("course save session details: (%s)" % str(e))
            response_dict['status'] = False
            response_dict['data'] = {}
            response_dict['message'] = 'no course data updated'
        return Response(response_dict)

###### TO GENERATE PASSWORD BASED ON USER GROUP WISE  ##############
class password_generation(ErrorMessage,View):
    
    def get(self,request):
        context = {}
        try:
            group_name = UserGroup.objects.values('group_name','pk')
            context =({"group_name" : group_name})
            context.update({"password_key":"PasswordGeneration"})
            context.update({"content":content.contents["college"]})
            ielite_logger.info("user_management \t college_usermanagements \t get method to load college level user page")
            return render(request, "new_include/password_generation.html",context=context)
        except Exception as e:
            pass
            ielite_except_logger.critical('user_management \t college_usermanagements \t '+str(e) +'\n'+ str(traceback.format_exc()))
            return render(request, "new_include/password_generation.html",context=context)


##### get user group name and get list of users and their password based on group name selection #######
from django.contrib.auth.models import AbstractUser
from rest_framework.permissions import AllowAny
from student_management.methods import random_password
class UserGroupList(ErrorMessage,APIView):
    permission_classes = [AllowAny]

    '''
    this get request represents to get the list of users and their passwords based on group name selection and without group also
    '''
    def get(serlf,request):
        response_dict = {"status":True,"message":"user list ","data":{}}
        try:
            # import ipdb;ipdb.set_trace()
            group_name = request.GET.get('group_name')
            if group_name:
                group = UserGroup.objects.get(pk=group_name)
                user_group_data = UserRoleMap.objects.filter(user_group_id=group,status=True).order_by('-created_on')
                list_user_group = []
                for each in user_group_data:
                # try:
                    aaa = StudentTmpPwd.objects.filter(student_temp_pwd=each.user_details_id.user).first()
                    each.user_details_id.user.set_password(aaa.code)
                    user_group = {}
                    user_group['username'] = aaa.student_temp_pwd.username
                    user_group['password'] = aaa.code
                    user_group['first_name'] = aaa.student_temp_pwd.first_name
                    user_group['email'] = aaa.student_temp_pwd.email if aaa.student_temp_pwd.email is not None else " "
                    list_user_group.append(user_group)
                response_dict['data'] = list_user_group
                return Response(response_dict)
            else:
                student_pwd = StudentTmpPwd.objects.all().order_by('-created_on')
                stud_pwd = []
                for i in student_pwd:
                    student_dict = {}
                    student_dict['username'] = i.student_temp_pwd.username
                    student_dict['password'] = i.code
                    student_dict['first_name'] = i.student_temp_pwd.first_name
                    student_dict['email'] = i.student_temp_pwd.email if i.student_temp_pwd.email is not None else " "
                    stud_pwd.append(student_dict)
                response_dict['data'] = stud_pwd
                return Response(response_dict)
                # except Exception as e:
                #     response_dict['message'] = 'data not found'
                #     return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['data'] = {}
            response_dict['message'] = 'data not found'
            return Response(response_dict)

    '''
    this post request represents to create the password based on group 
    '''        
    def post(self,request):
        result={}
        try:
            group_name = request.data.get('group_name')
            user_name = request.data.get('user_name')
            pwd = request.data.get('pwd')
            random_pwd = random_password()

            user_obj = UserRoleMap.objects.filter(user_details_id__user__username=user_name,user_group_id__group_name=group_name).first()
            user_obj.user_details_id.user.set_password(random_pwd)
            user_obj.save()
            aa = User.objects.get(username=user_name)
            cc = StudentTmpPwd.objects.create(student_temp_pwd=aa,code=random_pwd,created_by=request.user.id)
            result['status'] = True
            return Response({"status":True,"data":"pwd created successfully"})
        except Exception as e:
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return Response({"response":"pwd not created"+str(e)})

'''
 this class represents to create user group and get list of exam group
'''
class CreateGroup(ErrorMessage,APIView):
    permission_classes = [AllowAny]

    '''
    this get request represents to get the list of exam group data
    '''
    def get(self,request):
        response_dict = {"status":True,"message":"list of avaiilable groups ","data":{}}
        try:
            group_obj = UserGroup.objects.all().distinct('group_name')
            group_list = []
            for i in group_obj:
                group_data = {}
                group_data['group_name'] = i.group_name
                group_data['id'] = i.id
                group_list.append(group_data)
                response_dict['data'] = group_list
            return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['data'] = {}
            response_dict['message'] = 'data not found'
            return Response(response_dict)

    '''
    this post request represents to create the new unique user group 
    '''
    def post(serlf,request):
        try:
            response_dict = {'status':True,'message':'',"data":{}}
            group_name = request.data.get('group_name')

            if UserGroup.objects.filter(group_name=group_name):
                return Response({"response": 'User Group already Exist','status':False})
            else:
                group_obj = UserGroup.objects.create(group_name=group_name)
                response_dict['status'] = True
                response_dict['message'] = 'New user group created successfully'
                return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not found'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return Response(response_dict)


from mirage.crypto import Crypto
'''
this class represents ro get the list of user's data
'''
class Users(ErrorMessage,APIView):
    def get(serlf,request):
        c=Crypto()
        response_dict = {"status":True,"message":"list of avaiilable user data ","data":{}}
        try:
            user = UserRoleMap.objects.select_related('user_details_id').all().order_by('-created_on')
            user_list = []
            for i in user:
                user_dict = {}
                user_dict['userid'] = i.user_details_id.user.pk
                user_dict['role'] = i.role_manager_id.name
                user_dict['login_id'] = i.user_details_id.user.username
                user_dict['first_name'] = c.decrypt(i.user_details_id.first_name if i.user_details_id.first_name is not None else " ")
                user_dict['last_name'] = c.decrypt(i.user_details_id.last_name if i.user_details_id.last_name is not None else " ")
                user_dict['full_name'] = c.decrypt(i.user_details_id.first_name if i.user_details_id.first_name is not None else " ") +" "+c.decrypt(i.user_details_id.last_name if i.user_details_id.last_name is not None else " ")
                # user_dict['last_name'] = c.decrypt(i.user_details_id.last_name if i.user_details_id.last_name is not None else " ")
                user_dict['is_active'] = i.user_details_id.user.is_active
                user_dict ['email'] =  c.decrypt(i.user_details_id.email_id if i.user_details_id.email_id is not None else " ")
                user_list.append(user_dict)
                response_dict['data'] = user_list
            return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['data'] = {}
            response_dict['message'] = "data not found"
            return Response(response_dict)

    '''
    this post request represents to create new users in database
    '''

    def post(self, request):
        response_dict = {'status': True, 'message': '', "data": {}}
        try:
            c = Crypto()
            username = request.data.get('username')
            email_id = c.encrypt(request.data.get('email_id'))
            first_name = c.encrypt(request.data.get('first_name'))
            phone_no = c.encrypt(request.data.get('phone_no'))
            address1 = c.encrypt(request.data.get('address1'))
            group_name = request.data.get('group_name')
            last_name = c.encrypt(request.data.get('last_name'))
           
            role = request.data.get('role')
            if User.objects.filter(username=username):
                return Response({"response": 'User already Exist', 'status': False})
            
            else:
                random_pwd = random_password()
                new_user = User.objects.create(username=username,first_name=first_name,last_name=last_name)
                new_user.set_password(random_pwd)
                new_user.save()
                student_temp = StudentTmpPwd.objects.create(student_temp_pwd=new_user, code=random_pwd,created_by=request.user.id)

                user_data = User.objects.get(username__iexact=username)
                device_user_id, passcode = generate_device_id()
                user_role = RoleManager.objects.get(name=role)
                user_role_map = new_user.groups.add(user_role)
                
                if group_name is not '':
                    user_group = UserGroup(group_name=group_name,user=user_data)
                    user_group.save()
                user_group=None
                if email_id:
                    UserDetails.objects.filter(email_id=email_id)
                else:
                    pass
                user_detail = UserDetails(user=user_data,
                                          email_id=email_id,
                                          first_name=first_name,
                                          last_name = last_name,
                                          phone_no=phone_no,
                                          address1=address1,
                                          created_by=1,
                                          device_user_id=device_user_id,
                                          object_id=1,
                                          title=1,
                                          gender=1)
                user_detail.save()

                user_role = UserRoleMap(user_details_id=user_detail,
                                        role_manager_id=user_role,
                                        user_group_id=user_group,
                                        permanent_role=True,
                                        priority_role=True,
                                        is_active=True,
                                        object_id='123123',
                                        start_time='2020-04-20 06:00:00.000000-08:00',
                                        end_time='2030-04-20 06:00:00.000000-08:00',
                                        # user_group_id=user_group,
                                        created_by=1)

                user_role.save()

                response_dict['status'] = True
                response_dict['message'] = 'New user created successfully'
                return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not saved'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return Response(response_dict)

    '''
    this put request represents to update(edit) user details from front-end
    '''

    def put(self, request):
        response_dict = {"status": True, "message": "data updated", "data": {}}
        try:
            #import ipdb;ipdb.set_trace()
            user_id = request.data.get('user_id')
            email = request.data.get('email_id')
            first_name = request.data.get('first_name')
            role = request.data.get('role')
            address1 = request.data.get('address1')
            phone_no = request.data.get('phone_no')
            group_name = request.data.get('group_name')
            last_name = request.data.get('last_name')

            device_user_id, passcode = generate_device_id()

            user_instanec = User.objects.get(username=user_id)
            user_role_instance = RoleManager.objects.get(name=role)
            user_role_map = user_instanec.groups.add(user_role_instance)
            user_group = UserGroup.objects.get_or_create(group_name=group_name)

            userdata = User.objects.filter(username=user_id)
            if not userdata.exists():
                return Response({"status": False, "message": "user does not exist"})

            user_update = userdata.update(email=email, first_name=first_name)

            userdetail = UserDetails.objects.filter(user=userdata)
            usedetail_instance = UserDetails.objects.get(user=userdata)
            userdetail_update = UserDetails.update(first_name=first_name,
                                                   last_name=last_name,
                                                   email_id=email,
                                                   phone_no=phone_no,
                                                   address1=address1,
                                                   photo=photo,
                                                   created_by=request.user.id,
                                                   device_user_id=device_user_id,
                                                   object_id=1,
                                                   title=1,
                                                   gender=1)
            UserRoleMap.objects.update_or_create(user_details_id=usedetail_instance,
                                                 created_by=1,
                                                 role_manager_id=user_role_instance,
                                                 user_group_id=user_group[0],
                                                 permanent_role=True,
                                                 priority_role=True,
                                                 is_active=True,
                                                 object_id='123123',
                                                 start_time='2020-04-20 06:00:00.000000-08:00',
                                                 end_time='2030-04-20 06:00:00.000000-08:00', )
            return Response(response_dict)
            response_dict['status'] = True
            response_dict['message'] = "data updated"

        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not updated'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return Response(response_dict)



class UsersActiveInactive(ErrorMessage,APIView):
    def put(serlf,request):
        response_dict = {"status":True,"message":"user active status updated ","data":{}}
        try:
            status = request.data.get('status')

            user = User.objects.filter(username=request.data.get('username'))
            if user:
                user.update(is_active = status)
            else:
                response_dict = {"status":False,"message":"user not found"}
            return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['data'] = {}
            response_dict['message'] = "data not found"
            return Response(response_dict)




'''
this class represents to get list of roles
'''

class RoleData(ErrorMessage,APIView):
    def get(serlf,request):
        response_dict = {"status":True,"message":"list of avaiilable role data ","data":{}}
        try:
            user = RoleManager.objects.all().order_by('-created_on')
            user_list = []
            for i in user:
                user_dict = {}
                user_dict['role'] = i.name
                user_list.append(user_dict)
                response_dict['data'] = user_list
            return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['data'] = {}
            response_dict['message'] = "data not found"
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return Response(response_dict)
    ## to save new users in database ###########
    # def post(self,request):
    #     response_dict = {'status':True,'message':'',"data":{}}
    #     try:
    #         username = request.data.get('username')
    #         email_id = request.data.get('email_id')
    #         first_name = request.data.get('first_name')
    #         phone_no = request.data.get('phone_no')
    #         address1 = request.data.get('address1')
    #         group_name = request.data.get('group_name')
    #         role = request.data.get('role')

    #         if User.objects.filter(username = username):
    #             return Response({"response": 'User already Exist','status':False})
    #         elif User.objects.filter(email=email_id):
    #             return Response({"response": 'email already Exist','status':False})
    #         else:
    #             password = random_password()
    #             new_user = User.objects.create(username=username,email=email_id,first_name=first_name)
    #             new_user.set_password(password)
    #             new_user.save()
    #             student_temp = StudentTmpPwd.objects.create(student_temp_pwd=new_user,code=password)
    #             print(student_temp)

    #             user_data = User.objects.get(username=username)
    #             user_email = User.objects.get(email=email_id)
    #             device_user_id,passcode = generate_device_id()

    #             user_role = RoleManager.objects.get(name=role)
    #             user_role_map = new_user.groups.add(user_role)
    #             user_group = UserGroup.objects.get_or_create(group_name=group_name)
                
    #             user_detail = UserDetails(user=user_data,
    #                                       email_id=email_id,
    #                                       first_name=first_name,
    #                                       phone_no=phone_no,
    #                                       address1=address1,
    #                                       created_by=1,
    #                                       device_user_id=device_user_id,
    #                                       object_id = 1,
    #                                       title=1,
    #                                       gender=1)
    #             user_detail.save()

    #             user_role = UserRoleMap(user_details_id=user_detail,
    #                                     role_manager_id=user_role,
    #                                     user_group_id=user_group[0],
    #                                     permanent_role=True,
    #                                     priority_role=True,
    #                                     is_active= True,
    #                                     object_id = '123123',
    #                                     start_time='2020-04-20 06:00:00.000000-08:00',
    #                                     end_time = '2030-04-20 06:00:00.000000-08:00',
    #                                     # user_group_id=user_group,
    #                                     created_by=1)
    #             user_role.save()

    #             response_dict['status'] = True
    #             response_dict['message'] = 'New user created successfully'
    #             return Response(response_dict)
    #     except Exception as e:
    #         response_dict['status'] = False
    #         response_dict['message'] = 'data not saved'
    #         ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
    #         return Response(response_dict)

# ######### to get list of roles ##########
# class RoleData(APIView):
#     def get(serlf,request):
#         response_dict = {"status":True,"message":"list of avaiilable role data ","data":{}}
#         try:
#             user = RoleManager.objects.all().order_by('-created_on')
#             user_list = []
#             for i in user:
#                 user_dict = {}
#                 user_dict['role'] = i.name
#                 user_list.append(user_dict)
#                 response_dict['data'] = user_list
#             return Response(response_dict)
#         except Exception as e:
#             response_dict['status'] = False
#             response_dict['data'] = {}
#             response_dict['message'] = "data not found"
#             ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
#             return Response(response_dict)


'''
 this class represents to create a new role
 '''
class RoleCreation(ErrorMessage,APIView):
    def post(self,request):
        response_dict = {'status':True,'message':'',"data":{}}
        try:
            role_name = request.data.get('role_name')

            if RoleManager.objects.filter(name=role_name):
                return Response({"response": 'Role already Exist','status':False})
            content_type = ContentType.objects.get(app_label='college_management',model='collegedetails')
            new_role = RoleManager.objects.create(name=role_name,created_by=1,content_type=content_type)
            response_dict['status'] = True
            response_dict['message'] = 'New role created successfully'
            return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not saved'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return Response(response_dict)


'''
 naveen code starts here for user to course mapping through bulk upload
 '''

'''this function is for download template with student login id with course name
'''
from user_management import config, bulk_upload
from user_management.methods import user_column_headers,user_programme_data_type,user_mandatory_fields
def user_course_bulkdownload(request):
    module = request.GET.get('module_name')
    file_path = bulk_upload.create_filepath('student_management', 'user_course_info')
    df = pd.DataFrame()
    writer = pd.ExcelWriter(file_path, engine='xlsxwriter')
    workbook  = writer.book
    worksheet = workbook.add_worksheet('user_course_map')
    hidden_worksheet=workbook.add_worksheet('Dropdowns')
    worksheet.set_row(0,45)
    headers = user_column_headers(module)
    unlocked = workbook.add_format()
    unlocked.set_locked(False)
    header_format = workbook.add_format(bulk_upload.excel_formats()[0])
    mandatory_format = workbook.add_format(bulk_upload.excel_formats()[2])
    count=0
    mandatory_field_check = user_mandatory_fields(module)
    for i in headers: 
        if  isinstance(i, dict):
            for key, val in i.items():
                worksheet.write(0, count, key, mandatory_format)
                dropdown_range  = bulk_upload.hidden_column_dropdown(hidden_worksheet, val, headers.index(i), 'Dropdowns')
                bulk_upload.data_validation(count, worksheet, None, dropdown_range, key)
        else:
            if i in mandatory_field_check:
                worksheet.write(0, count, i, mandatory_format)
                data = bulk_upload.data_attributes(i, user_programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)

            else:
                worksheet.write(0, count, i, header_format)
                data = bulk_upload.data_attributes(i, user_programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
        count = count+1
    hidden_worksheet.hide()
    worksheet.protect()
    worksheet.set_column('A:M',20, unlocked)
    writer.save()
    workbook.close()
    return bulk_upload.download_template(file_path)

'''
this class reprensents to upload user to course mapping excel sheet  and save it in database
 '''
class user_course_bulkupload(ErrorMessage,View):

    def post(self, request):
        try:
            http_protocol = 'http://'
            if request.is_secure():
                http_protocol = 'https://'
            host = http_protocol+request.META['HTTP_HOST']
            # import ipdb;ipdb.set_trace()
            prog_file= request.FILES.get('file')
            module = request.GET.get('module_name')
            validate_count = request.GET.get('validate')
            '''
            "sheetname" has renamed to "sheet_name" because of it seems that this "sheet_name" could be language dependent
            '''
            df = pd.read_excel(prog_file, header=0, sheet_name='user_course_map')
            df2 = pd.DataFrame(columns=['Course Id', 'User Id', 'Department', 'Academic Session', 'Error Message'])
            df = df.replace(np.nan, '', regex=True)
            '''
            to create or map exam series(course) to department and academic
            '''
            # Exam_Exam_code=random.randint(1000,9999)
            
            coursenames = NewExamSeries.objects.filter(exam_series_name=df['Course Id'])
            
            department = Departments.objects.get_or_create(department_name=df['Department'][0],created_by=request.user.id)
            academic = AcademySession.objects.get_or_create(session_name=df['Academic Session'][0],created_by=request.user.id)
            
            if not department and academic.exists():
                exam_series = NewExamSeries.objects.filter(exam_series_name = coursenames).update(under_department=df['Course Id'][0],under_session=df['Academic Session'][0])                
            # else:
                # exam_series = NewExamSeries.objects.filter(exam_series_name = coursenames).update(under_department=department,under_session=academic)
            # import ipdb; ipdb.set_trace();
            exisitng_count = 0
            empty_fields_count = 0
            course_does_not_exist_count = 0            
            user_does_not_exist_count = 0
            new_user_created_count=0
            for i in range(df['User Id'].count()):
                mandatory_check = check_mandatory(df, user_mandatory_fields, 'UserCourses', i)
                if all(i == 'false' for i in mandatory_check):
                    try:
                        # Exam_Exam_code=random.randint(1000,9999)

                        username = UserDetails.objects.filter(user__username = df['User Id'][i])
                        coursename = NewExamSeries.objects.filter(exam_series_name=df['Course Id'][i])
                        # course_data = NewExamSeries.objects.filter(exam_series_name=coursename)
                        if username:
                            if coursename:
                                course_student = EvaluatorToExamgroup.objects.filter(user_details__user__username= username[0].user.username,subject__exam_series_name=coursename[0].exam_series_name)
                                if course_student.exists():
                                    exisitng_count += 1
                                    # df.loc[i,'Comment'] = 'Data already exists for same student login id for that course'
                                    # continue
                                    error_msg = "User to Course mapping already exists."
                                    user = df.iloc[[i]]
                                    df2 = df2.append(user, sort = False)
                                    df2.loc[i, "Error Message"] = error_msg

                                    # return JsonResponse({"comment":"user to course map already exist"})
                                else:
                                    user_course_mapping = EvaluatorToExamgroup(user_details= username[0],subject=coursename[0],created_by=1)    
                                    user_course_mapping.save()
                                    new_user_created_count = new_user_created_count+1
                            else:
                                # pass
                                error_msg = "This Course does not exist."
                                course_does_not_exist_count += 1
                                user = df.iloc[[i]]
                                df2 = df2.append(user, sort = False)
                                df2.loc[i, "Error Message"] = error_msg

                                # return JsonResponse({"comment":"course does not exist"})
                        else:
                            error_msg = "This User does not exist."
                            user_does_not_exist_count += 1
                            user = df.iloc[[i]]
                            df2 = df2.append(user, sort = False)
                            df2.loc[i, "Error Message"] = error_msg


                       
                    except Exception as e:
                        return JsonResponse({str(e)})
                else:
                    # return JsonResponse({"comment":"missing mandatory fields"})
                    error_msg = "Mandatory Fields are Empty!"
                    empty_fields_count += 1
                    user = df.iloc[[i]]
                    df2 = df2.append(user, sort = False)
                    df2.loc[i, "Error Message"] = error_msg

            # print("NEW USER-MAPPING CREATED COUNT", new_user_created_count)


            # import ipdb; ipdb.set_trace();
            now = datetime.now()
            time_now = now.strftime("%d-%m-%Y-%H-%M")


            main_folder_path = "media/error_reports"
            abs_main_file_path = os.path.join(settings.BASE_DIR, main_folder_path)

            if not os.path.exists(abs_main_file_path):
                os.mkdir(abs_main_file_path)

            user_error_report_path = "/user_course_mapping_bulk_upload"
            abs_folder_path = abs_main_file_path + user_error_report_path

            if not os.path.exists(abs_folder_path):
                os.mkdir(abs_folder_path)

            user_file_name = "/" + time_now + "___" + str(prog_file.name)

            abs_media_path = abs_folder_path + user_file_name

            media_path = main_folder_path + user_error_report_path + user_file_name
            file_path = host + "/" + media_path



            df2.to_excel(abs_media_path, index=False)

            return JsonResponse({"msg": 'data uploaded successfully', "file_path":file_path, "prog_def_count": str(df['User Id'].count()), 
                "exisitng_count": str(exisitng_count), "empty_fields_count": str(empty_fields_count), 
                "course_does_not_exist_count": str(course_does_not_exist_count), "user_does_not_exist_count": str(user_does_not_exist_count),
                 "new_user_created_count": str(new_user_created_count)})
            if request.GET.get('validate') =='true':
                current_path = os.getcwd()
                # dt = str(datetime.datetime.now())
                op_path = current_path+'/user_management/excel_templates/'+ str(prog_file)
                # df2.to_excel(op_path)
                return JsonResponse({"file_path":file_path, "prog_def_count": str(new_user_created_count), 
                    "invalid_data": str(count)})
        except Exception as e:
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return JsonResponse({"error":"invalid_file"})


###### send email to user  ##########
def send_activation_email(request, user):
    subject = "You have received email activation!"
    current_site = get_current_site(request)
    to_user = User.objects.get(pk=request.GET.get('user_id')).username
    to_email = User.objects.get(pk=request.GET.get('user_id')).email
    import random as r

    # random_number = otp_generate(4)
    # otp=""
    # for i in range(4):
    #     otp+=str(r.randint(1,9))
    #     otps=otp
    tpl= 'registration/email_sending.html'
    ctx = { 'user': to_user, 
            'domain': current_site.domain, 
            'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
            'token': account_activation_token.make_token(user),
            # 'otp':otps
       }

    html_message = render_to_string(tpl, ctx)
    send_mail(
        subject=to_user ,
        message='', # Plain text version of message - advisable to provide this
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[to_email],
        html_message=html_message
    )


'''
this class reprensents to create a directory,file and write the json data into that file and read the data from file
'''
class Writejson(ErrorMessage,APIView):
    path = settings.MEDIA_ROOT+'json_folder/'+'test.json'
    
    def post(self,request):
        response_dict = {'status':True,'message':'',"data":{}}
        try:
            json_data=request.data.get('json')
            path = settings.MEDIA_ROOT+'json_folder/'+'test.json'
            with open(self.path, 'w') as outfile:
                data = json.dump(json_data,outfile)
                return Response(response_dict)
        except Exception as e:
             response_dict['status'] = False
             response_dict['message'] = 'data not created'
             ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)


    def get(self,request):
        response_dict = {"status":True,"message":"data is available ","data":{}}
        try:
            # import ipdb;ipdb.set_trace()
            with open(self.path,'rb') as json_files:
                data = json.load(json_files)
                response_dict['data'] = data
                return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not available'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)



'''
this function represents to redirect to url
'''

def urldirect(request):
    return HttpResponseRedirect("http://35.244.28.33:8000/")  
    



class UserFirstTimePwd(ErrorMessage,APIView):

    def get(self,request):
        response_dict = {"status":True,"message":"data is available ","data":{}}
        c=Crypto()
        try:
            user_obj = StudentTmpPwd.objects.all().order_by('-created_on')
            user_list=[]
            for i  in user_obj:
                user_dict={}
                user_dict['userid'] = i.student_temp_pwd.pk
                user_dict['username'] = i.student_temp_pwd.username
                user_dict['email'] = c.decrypt(i.student_temp_pwd.email)
                user_dict['password'] = i.code
                user_list.append(user_dict)
                response_dict['data'] = user_list
            return Response(response_dict)
        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not available'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)

    def post(self,request):
        response_dict = {"status":True,"message":"data is saved"}

        try:
            username = request.data.get('username')
            pwd = request.data.get('password')

            user_data = User.objects.get(username=username)
            if user_data:
                user_data.set_password(pwd)
                user_data.save()
                student_temp = StudentTmpPwd.objects.filter(student_temp_pwd=user_data).update(code=pwd)
                return Response(response_dict)
            else:
                return Response({"msg":"user does not exist"})
        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not saved'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)


### thsi api class represents to handle the session timeout ############3
class SessionTimeout(ErrorMessage,APIView):
    def get(self,request):
        response_dict = {"status": True, "message": "", "data": {}}
        try:
             if request.user.is_authenticated():
                return HttpResponse("authenticated")
             else:
                return HttpResponse("not authenticated")
                
        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not saved'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)


'''
this class represents to validate the user
'''
class user_validation(ErrorMessage,View):
    def get(self,request):
        
        response_dict = {}
        try:
            user_id = request.GET.get("value")
            username = User.objects.get(username=user_id)
            if UserRoleMap.objects.filter(role_manager_id__name='STUDENT',user_details_id__user__username=username):
                response_dict.update({"flag":"true"})
            else:
                response_dict.update({"flag":"false"})
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)
        except Exception as e:
            # pass
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return HttpResponse(json.dumps(response_dict), 
                        content_type='application/javascript',
                        status=200)


# ########### naveen code ends here ###################################


'''ADDED BY Venkata Praneeth on 10/09/2020'''
'''This function represents Proctor Main Page'''
def Proctor(request):
    return render(request,'proctor_main.html',locals())



def student_scan(request,):
    return render(request,'student_scan.html')




import os
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from dvs.models import AssignAssignmentTable
from rest_framework.parsers import MultiPartParser

class Img_upload(APIView):
    # import ipdb;ipdb.set_trace()
    def post(self,request):
        parser_classes = (MultiPartParser)

        response_dict = {'status':True,'message':'',"data":{}}
        try:
            # import ipdb;ipdb.set_trace()
            data = request.data.get('img')
            path = default_storage.save('json_folder/'+data.name, ContentFile(data.read()))
            tmp_file = os.path.join(settings.MEDIA_ROOT, path)
        except Exception as e:
             response_dict['status'] = False
             response_dict['message'] = 'data not created'
             kencloud_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)





from dvs.models import AssignAssignmentTable
from online_exam.models import QuestionPaper,AssignOnlineExamTable

class StudentData(APIView):
    # permission_classes = [permissions.AllowAny]
    '''  student QP  '''
    def get(self,request):
        #import ipdb;ipdb.set_trace()

        # exam_obj = request.GET.get('exam_id')
        # exam_instance = QuestionPaper.objects.get(qp_id=exam_obj)

        # obj = AssignAssignmentTable.objects.filter(student__user__username='sweety',exam__id = 776)
        obj = AssignOnlineExamTable.objects.filter(student_id__user__username='sweety',exam_id__id=111,)

        result = []
        for each in obj:
            d={}
            try:
                d['student_name'] = each.student.user.username
                d['exam_id'] = each.exam.id
                d['qp'] = each.exam.qp_id.qp_json
            except:
                pass

            result.append(d)
        return Response(result)


from .models import MyEvent as MyEvents
'''
This class api represents to store event logging
'''
class MyLog(APIView):

    def post(self,request):

        response_dict = {'status':True,'message':'',"data":{}}

        try:
            username = request.data.get('bUserID')
            action = request.data.get('bAction')
            description = request.data.get('bDescription')
            role = request.data.get('bUserRole')

            user_instanec = User.objects.get(pk=username)
            role_magr_instance = RoleManager.objects.get(name=role)
            obj = MyEvents.objects.create(user=user_instanec,action=action,description=description,user_role=role_magr_instance)
            return Response(response_dict)

        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not saved'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)




from user_management.methods import group_column_headers,group_programme_data_type,group_mandatory_fields
'''
user to group bulk sheet download
'''
def user_group_bulkdownload(request):
    module = request.GET.get('module_name')
    file_path = bulk_upload.create_filepath('user_management', 'user_group_info')
    df = pd.DataFrame()
    writer = pd.ExcelWriter(file_path, engine='xlsxwriter')
    workbook  = writer.book
    worksheet = workbook.add_worksheet('user_group_map')
    hidden_worksheet=workbook.add_worksheet('Dropdowns')
    worksheet.set_row(0,45)
    headers = group_column_headers(module)
    unlocked = workbook.add_format()
    unlocked.set_locked(False)
    header_format = workbook.add_format(bulk_upload.excel_formats()[0])
    mandatory_format = workbook.add_format(bulk_upload.excel_formats()[2])
    count=0
    mandatory_field_check = group_column_headers(module)
    for i in headers: 
        if  isinstance(i, dict):
            for key, val in i.items():
                worksheet.write(0, count, key, mandatory_format)
                dropdown_range  = bulk_upload.hidden_column_dropdown(hidden_worksheet, val, headers.index(i), 'Dropdowns')
                bulk_upload.data_validation(count, worksheet, None, dropdown_range, key)
        else:
            if i in mandatory_field_check:
                worksheet.write(0, count, i, mandatory_format)
                data = bulk_upload.data_attributes(i, group_programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)

            else:
                worksheet.write(0, count, i, header_format)
                data = bulk_upload.data_attributes(i, group_programme_data_type)
                bulk_upload.data_validation(count, worksheet, data, None, i)
        count = count+1
    hidden_worksheet.hide()
    worksheet.protect()
    worksheet.set_column('A:M',20, unlocked)
    writer.save()
    workbook.close()
    return bulk_upload.download_template(file_path)

'''
user to group bulkupload mapping
'''
class user_group_bulkupload(ErrorMessage,View):

    def post(self, request):

        try:
            prog_file= request.FILES.get('file')
            module = request.GET.get('module_name')
            validate_count = request.GET.get('validate')
        
            df = pd.read_excel(prog_file, header=0, sheet_name='user_group_map')
            df = df.replace(np.nan, '', regex=True)
            count = 0 
            
            for i in range(df['User Id'].count()):
                mandatory_check = check_mandatory(df, group_mandatory_fields, 'UserGroup', i)
                if all(i == 'false' for i in mandatory_check):
                    try:

                        user_instance = User.objects.get(username= df['User Id'][i])
                        group_instance = UserGroup.objects.filter(group_name = df['Group'][i])
                        

                        group_obj = UserGroup(group_name=group_instance[0],user=user_instance)
                        group_obj.save()
                        
                    except Exception as e:
                        return JsonResponse({str(e)})
                else:
                    return JsonResponse({"comment":"missing mandatory fields"})
            if request.GET.get('validate') =='true':
                current_path = os.getcwd()
                # dt = str(datetime.datetime.now())
                op_path = current_path+'/user_management/excel_templates/'+ str(prog_file)
                df.to_excel(op_path)
                return JsonResponse({"file_path":op_path, "prog_def_count": str(df['User Id'].count()), 
                    "invalid_data": str(count)})
        except Exception as e:
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return JsonResponse({"error":"invalid_file"})

'''
get list of users based on group selection
'''
class UserGroupMapping(ErrorMessage,APIView):
    permission_classes = [AllowAny]
    def get(self,request):
        c = Crypto()
        response_dict = {"status":True,"message":"available user list ","data":{}}
        try:
            group_name = request.GET.get('group_name')
            if group_name:
                user_group_data = UserGroup.objects.filter(group_name=group_name)
                list_user_group = []
                for each in user_group_data:
                    user_group = {}
                    user_group['username'] = each.user.username
                    user_group['email'] = c.decrypt(each.user.email)
                    user_group['first_name'] = each.user.first_name
                    list_user_group.append(user_group)
                response_dict['data'] = list_user_group
                return Response(response_dict)

        except Exception as e:
            response_dict['status'] = False
            response_dict['message'] = 'data not found'
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
        return Response(response_dict)


'''
Email sending
'''
from django.core import mail

class EmailSending(APIView):
    def get(self,request):

        try:
            c = Crypto()
            connection = mail.get_connection()
            
            subject = "You have received email activation!"
            import random as r
            http_protocol = 'http://'
            if request.is_secure():
                http_protocol = 'https://'
            host=http_protocol+request.META['HTTP_HOST']

            users = User.objects.all()
            connection.open()
            for user in users:
                
                pwd = StudentTmpPwd.objects.filter(student_temp_pwd=user.pk)
                if pwd:
                    tpl= 'registration/email_sending.html'
                    ctx = { 'user': user.username, 
                            'host_name': request.GET.get('url'), 
                            'password':pwd[0].code ,
                            'f_name':c.decrypt(user.first_name),
                       }

                    html_message = render_to_string(tpl, ctx)
                    send_mail(
                        subject='Credentials' ,
                        message='', # Plain text version of message - advisable to provide this
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[c.decrypt(user.email)],
                        html_message=html_message
                    )
            connection.open()
            return Response({"status":True,"msg":"email has sent successfully"})


        except Exception as e:
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return JsonResponse({"error":"invalid_email"})





def changePassword(request):
    return render(request,'new_include/forgot_password.html')

'''
this class represents to reset password and send email to user with password
'''
class ResetPwdSending(APIView):
    def post(self,request):
        try:
            import random as r
            password = random_password()
            c = Crypto()
            subject = "You have received email activation!"
            current_site = get_current_site(request)
            to_user = User.objects.get(pk=request.data.get('user_id')).username
            to_email = User.objects.get(pk=request.data.get('user_id')).email
            first_name = c.decrypt(User.objects.get(pk=request.data.get('user_id')).first_name)
            
            user_pwd = User.objects.get(username=to_user)
            if user_pwd:
                user_pwd.set_password(password)
                user_pwd.save()
                passwords = StudentTmpPwd.objects.filter(student_temp_pwd=user_pwd).update(code=password)
                reset_pwd = StudentTmpPwd.objects.get(student_temp_pwd=request.data.get('user_id')).code
                # print(reset_pwd)
            too_email = c.decrypt(to_email)
            tpl= 'registration/reset_pwd.html'
            ctx = { 'user': to_user, 
                    'domain': current_site.domain, 
                    'uid': urlsafe_base64_encode(force_bytes(request.user.pk)).decode(),
                    'token': account_activation_token.make_token(request.user),
                    'reset_pwd': reset_pwd,
                    'first_name':first_name,
                    # 'otp':otps
               }

            html_message = render_to_string(tpl, ctx)
            send_mail(
                subject=to_user ,
                message='', # Plain text version of message - advisable to provide this
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[too_email],
                html_message=html_message
            )
            return Response({"status":True,"msg":"email has sent successfully"})


        except Exception as e:
            ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
            return JsonResponse({"error":"invalid_email"})



# random_pwd = random_password()
#                 new_user = User.objects.create(username=username,first_name=first_name,last_name=last_name)
#                 new_user.set_password(random_pwd)
#                 new_user.save()
#                 student_temp = StudentTmpPwd.objects.create(student_temp_pwd=new_user, code=random_pwd,created_by=request.user.id)


# user_data = User.objects.get(username=username)
#             if user_data:
#                 user_data.set_password(pwd)
#                 user_data.save()
        

#     def get(self,request):

#         response_dict = {"status":True,"message":"data is available ","data":{}}

#         try:
#             obj1 =AssignAssignmentTable.objects.filter(student__user=request.user.id)
#             if not obj1.exists():
#                response_dict[{'status':False,'message':'Userdetails not registered'}]
#             else:
#                obj = obj1.get()
#                response_dict['data']={'id':obj.student.user.username}


#         except Exception as e:
#             response_dict['status'] = False
#             response_dict['message'] = 'data not available'
#             ielite_except_logger.critical(str(e) + '\n' + str(traceback.format_exc()))
#         return Response(response_dict)


            # obj1 =UserDetails.objects.filter(user=request.user.id)
            # if not obj1.exists():
            #     response_dict[{'status':False,'message':'Userdetails not registered'}]
            # else:
            #     obj = obj1.get()
            #     response_dict['data']={'id':obj.user.username,'img':host+'/media/'+obj.photo.url}



    # def post(self,request):
    #     request1 = eval(request.data.get('data'))
    #     student_id = request1.get("student_id")
    #     name = request1.get("name")
    #     subject_id = request1.get("subject_id")
    #     annotation_file = request.FILES.get('file0')
    #     obj = AnswerScriptUpload.objects.create(created_by=1,
    #                                     student_id=student_id,
    #                                     student_name = name,
    #                                     subject_id = subject_id,
    #                                     annotation_file = annotation_file)
    #     obj = {"status":True,"messages":True}
    #     return Response(obj)



    # def delete(self,request,pkid):
    #     student_info = get_or_none(AnswerScriptUpload, pk=pkid)
    #     if student_info:
    #         student_info.status= False
    #         student_info.save()
    #     return Response({"status":True})
