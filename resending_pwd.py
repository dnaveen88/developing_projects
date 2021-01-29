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
