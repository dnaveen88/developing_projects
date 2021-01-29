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



====================== ========================== ==============================

##methods.py for mandatory fields

from user_management.models import UserGroup
from collections import OrderedDict
from django.contrib.auth.models import User

def column_headers(module):
    # import ipdb;ipdb.set_trace()
    if module == 'CollegeUser':
        column_list=[
                    # {'Programme Type':[x['programme_type_code'] for x in ProgrammeType.objects.filter(status=True).values('programme_type_code').distinct()]}, 
                    # {'Stream':[x['stream_code'] for x in Stream.objects.filter(status=True).values('stream_code').distinct()]}, 
                    # {'Degree Type':[x['degree_type_code'] for x in DegreeType.objects.filter(status=True).values('degree_type_code').distinct()]}, 
                    # {'Branch':[x['degree_branch_map_name'] for x in DegreeBranchMapping.objects.filter(status=True).values('degree_branch_map_name').distinct()]}, 
                    'User Id',
                    {'Role':[x['name'] for x in RoleManager.objects.filter(status=True).values('name').distinct()]},
                    'User First Name',

                    # {'Group Name':[x['group_name'] for x in UserGroup.objects.filter().values('group_name').distinct()]},
                    'User Email Id',  'User Last Name','Address1','Address2',
                    'Phone Number','Qualification','Designation','Experience','Specialization']
    else:
        # assess_type = [x['assessment_pattern_code'] for x in AssessmentPattern.objects.filter(status=True).values('assessment_pattern_code').distinct()]
        # assess_type.append('NA')
        # cycle_group = [x['cycle_group_code'] for x in CycleGroup.objects.filter(status=True).values('cycle_group_code').distinct()]
        # cycle_group.append('NA')
        column_list = [
                        # 'Programme',
                         # {'Role':[x['regulation_code'] for x in RegulationMaster.objects.filter(status=True).values('regulation_code').distinct()]},
                        # 'Assessment Number',  
                        # {'Lateral Assessment Type':assess_type}, 
                        # 'Regular Minimum Marks', 'Regular Maximum Marks', 'Regular Minimum Credit', 'Regular Maximum Credit',
                        # 'Lateral Minimum Marks', 'Lateral Maximum Marks', 'Lateral Minimum Credit', 'Lateral Maximum Credit',
                        # {'Regular Cycle Group': cycle_group},
                        # {'Lateral Cycle Group': cycle_group}
                        ]
    return column_list

def programme_data_type():
    data_type=[{'integer':['Assessment Number', 'Minimum Marks', 'Maximum Marks', 'Minimum Credit', 'Maximum Credit', 'Minimum Duration', 'Maximum Duration', 'Minimum Duration Lateral', 
    'Maximum Duration Lateral', 'Total Number Of Assessment']},{'char':['Programme Code', 'Programme Name']}]
    return data_type

def mandatory_fields(module):
    if module == 'CollegeUsers':
        mandatory_col = ['User Id','Role', 'User First Name']
    else:

        mandatory_col = ['User Id','Role','User First Name']
    return mandatory_col


