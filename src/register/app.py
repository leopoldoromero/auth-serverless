import json
import uuid
import boto3
from botocore.exceptions import ClientError
import os
import hashlib

cognito_client = boto3.client('cognito-idp')
dynamodb = boto3.resource('dynamodb')
user_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAME'])

def hash_password(password):
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + hashed_password

def register_handler(event, context):
    body = json.loads(event['body'])
    password = body['password']
    email = body['email']
    user_id = str(uuid.uuid4())
    user_name = email.split('@')[0] + user_id[:8]

    try:
        user_pool_id = os.environ['USER_POOL_ID']

        response = user_table.query(
            IndexName='EmailIndex',
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        
        if 'Items' in response and len(response['Items']) > 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Register failed', 'error': 'User already exist'})
            }
        
        response = cognito_client.admin_create_user(
            UserPoolId=user_pool_id,
            Username=user_name,
            UserAttributes=[
                {'Name': 'email', 'Value': email},
                {'Name': 'email_verified', 'Value': 'true'},
            ],
            TemporaryPassword=password,
            MessageAction='SUPPRESS'
        )
        cognito_client.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=user_name,
            Password=password,
            Permanent=True
        )
        
        cognito_sub = None
        for attr in response['User']['Attributes']:
            if attr['Name'] == 'sub':
                cognito_sub = attr['Value']
                break

        hashed_password = hash_password(password)
        user_table.put_item(
            Item={
                'id': user_id,
                'email': email,
                'password': hashed_password.hex(),
                'userName': user_name,
                'providerId': cognito_sub,
                'status': 'created',
            }
        )
        
        return {
            'statusCode': 201,
            'body': 'User registered successfully'
        }
    except ClientError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'message': 'Registration failed', 'error': str(e)})
        }

