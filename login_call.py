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
