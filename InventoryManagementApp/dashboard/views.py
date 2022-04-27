from pickle import FALSE
from django.shortcuts import render
from  django.http import HttpResponse, JsonResponse
from decouple import config
from dashboard import decode_jwt
from django.template.loader import render_to_string
from boto3.dynamodb.conditions import Key
import boto3
import base64
import requests
from django.conf import settings

fetchData = True
items = []
distinct_stores = []

# Create your views here.
def index(request):
    global fetchData 
    fetchData = True
    try:
        code = request.GET.get('code')
        print("+++++++++++++++++++++ Authorization Code +++++++++++++")
        print(code)
        token = getSession(request)
        if token is not None:
            userData = decode_jwt.lambda_handler(token, None)
            userData["id_token"] = token
            # print("----------------",userData)
        else:
            if not code:
                return render(request, 'dashboard/index.html', {'status': 0})
            userData = getToken(code)
        context = {
            'name': userData['name'],
            'status': 1
        } 
        print("Guess who is trying to log into our application ? - Its ", userData['name'])
        updated_context = getData(request,userData["id_token"])
        # print(updated_context)
        context['inventory_items'] = updated_context["items"]
        context['stores']= updated_context["distinct_stores"]

        response = render(request, 'dashboard/index.html', context)
        response.set_cookie('sessiontoken', userData['id_token'], max_age=60*60, httponly=True) 
        return response
        
    except:
        print("-----------------------INSIDE EXCEPTION---------------")
        token = getSession(request)
        if token is not None:
            userData = decode_jwt.lambda_handler(token, None)
            userData["id_token"] = token
            context = {
                'name': userData['name'],
                'status': 1
            } 
            updated_context = getData(request,userData["id_token"])
            context['inventory_items'] = updated_context["items"]
            context['stores']= updated_context["distinct_stores"]
            return render(request, 'dashboard/index.html', context)
        
        return render(request, 'dashboard/index.html', {'status': 0})
        # return render(request, 'dashboard/index.html', context)

def getToken(code):
    TOKEN_ENDPOINT = config('TOKEN_ENDPOINT')
    REDIRECT_URI = config('REDIRECT_URI')
    CLIENT_ID = config('CLIENT_ID')
    CLIENT_SECRET = config('CLIENT_SECRET')

    encoded_data = base64.b64encode(bytes(f"{CLIENT_ID}:{CLIENT_SECRET}","ISO-8859-1")).decode("ascii")
    # print("ENCODEDDDDDDDD DATA =================== ",encoded_data)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {encoded_data}'
    }

    body = {
        'grant_type': 'authorization_code',
        'client_id': CLIENT_ID,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }

    try:
        # print("----------Resp", TOKEN_ENDPOINT)
        resp = requests.post(TOKEN_ENDPOINT, data=body, headers=headers, verify=True)
        # print("+++++++++Resp", resp)
    except Exception as e:
        print(str(e))

    token = resp.json()['id_token']
    print("++++++++++++++ Authntication Token +++++++++++++++++++", token)
    userData = decode_jwt.lambda_handler(token,None)
    # print(userData)

    if not userData:
        return False
    user = {
        'id_token': token,
        'name': userData['name'],
        'email': userData['email']
    }
    return user


def getSession(request):
    try:
        response = request.COOKIES["sessiontoken"]
        return response
    except:
        return None

def getData(request,token = None):
    if token is None:
        token = getSession(request)
    global items, fetchData, distinct_stores
    refreshData = False
    client = boto3.client('cognito-identity','us-east-1')
    loggedInUser = client.get_id(
        IdentityPoolId='us-east-1:f07ab485-260c-4fea-b6b9-3e63f2772796',
        Logins={
            'cognito-idp.us-east-1.amazonaws.com/us-east-1_z5X83ceHN': token
        }
    )
    print("------------------Identity ID of Logged In User------------------------")
    print(loggedInUser)
    idenId = loggedInUser['IdentityId']

    resp = client.get_credentials_for_identity(
        IdentityId=idenId,
        Logins={
            'cognito-idp.us-east-1.amazonaws.com/us-east-1_z5X83ceHN': token
        }
    )
    print("----------------------TEMPORARY CREDENTIALS-------------------------")
    print(resp)

    tempCred=resp['Credentials'] 

    try:
        refresh = request.GET.get('inputValue')
        refreshData = refresh == 'true'
    except:
        pass

    if fetchData or refreshData:
        dynamodb = boto3.resource('dynamodb', aws_access_key_id= tempCred['AccessKeyId'], aws_secret_access_key=tempCred['SecretKey'], aws_session_token=tempCred['SessionToken'])
        table = dynamodb.Table('inventory')
        resp = table.scan()
        fetchData = False
        items = resp['Items']

        distinct_stores = list({ item['store'] for item in items})
        distinct_stores.insert(0,"All Stores")
        distinct_stores.sort()

    if refreshData:
        inv_details = render_to_string('dashboard/inventory_details.html', {'inventory_items':items})
        stores = render_to_string('dashboard/store_options.html', {'stores':distinct_stores})
        chartData = {
            "lab": [item["item_name"] for item in items],
            "count": [item["item_count"] for item in items]
        }
        data = {
            "inv_table": inv_details,
            "stores": stores, 
            "filtered_data": chartData
        }
        return JsonResponse(data)
    else:
        resp = {
            "items": items,
            "distinct_stores": distinct_stores
        }
        return resp
    # if selected_store and selected_store!='All Stores':
    #     items_to_display = list(item for item in items if item['store']==selected_store)
    #     distinct_stores.remove(selected_store)
    #     distinct_stores.insert(0,selected_store)
    # else:
    #     items_to_display = items
    #
    # print(items_to_display)

def signOut(request):
    response = render(request, 'dashboard/index.html', {'status':0})
    response.delete_cookie("sessiontoken")
    return response

def store(request):
    user_input = request.GET.get('inputValue')
    data = {'response': f'You typed: {user_input}'}
    # print(user_input)
    global items
    if user_input == 'All Stores':
        x = items
    else:
        x = [item for item in items if item['store']==user_input]
    # print(x)
    inv_details = render_to_string('dashboard/inventory_details.html', {'inventory_items':x})
    chartData = {
        "lab": [item["item_name"] for item in x],
        "count": [item["item_count"] for item in x]
    }
    data = {
        "inv_table": inv_details,
        # "chart": charts,
        "filtered_data": chartData
    }
    return JsonResponse(data)