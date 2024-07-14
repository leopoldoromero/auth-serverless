import json
import boto3
from botocore.exceptions import ClientError
import os
import hashlib

cognito_client = boto3.client('cognito-idp')
dynamodb = boto3.resource('dynamodb')
user_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAME'])

def check_password(stored_password, provided_password):
    salt = stored_password[:16]
    stored_password = stored_password[16:]
    hashed_password = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return hashed_password == stored_password


def login_handler(event, context):
    body = json.loads(event['body'])
    email = body['email']
    password = body['password']

    try:
        response = user_table.query(
            IndexName='EmailIndex',
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        
        if 'Items' not in response or len(response['Items']) == 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Register failed', 'error': 'User already exist'})
            }
    
        user = response['Items'][0]
        stored_password = user['password']
        user_id = user['id']
        user_name = user['userName']
        
        if check_password(stored_password, password):
             return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Login failed', 'error': 'Incorrect email or password'})
            }


        cognito_response = cognito_client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': user_name,
                'PASSWORD': password
            },
            ClientId=os.environ['USER_POOL_CLIENT_ID']
        )
        user_table.update_item(
            Key={'id': user_id},
            UpdateExpression='SET #status = :val1',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':val1': 'loggedin'}
        )
        access_token = cognito_response['AuthenticationResult']['AccessToken']
        refresh_token = cognito_response['AuthenticationResult']['RefreshToken']

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Login successful', 'access_token': access_token, 'refresh_token': refresh_token})
        }
    except ClientError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'message': 'Login failed', 'error': str(e)})
        }
