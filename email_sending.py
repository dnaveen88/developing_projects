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
