import json
import boto3
from botocore.exceptions import ClientError
import os

cognito_client = boto3.client('cognito-idp')
dynamodb = boto3.resource('dynamodb')
user_table = dynamodb.Table(os.environ['DYNAMODB_TABLE_NAME'])

def logout_handler(event, context):
    cognito_sub = event['requestContext']['authorizer']['jwt']['claims']['sub']
    try:
        response = user_table.scan(
            FilterExpression='providerId = :providerId',
            ExpressionAttributeValues={':providerId': cognito_sub}
        )
        
        if 'Items' not in response or len(response['Items']) == 0:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'User not found'})
            }
        
        user = response['Items'][0]
        user_name = user['userName']
        
        response = cognito_client.admin_user_global_sign_out(
            UserPoolId=os.environ['USER_POOL_ID'],
            Username=user_name
        )
        user_table.update_item(
            Key={'userName': user_name},
            UpdateExpression='SET #status = :val1',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':val1': 'loggedout'}
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Logout successful'})
        }
    except ClientError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'message': 'Logout failed', 'error': str(e)})
        }
