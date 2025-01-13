# Auth serverless

## Overview

This project provides an authentication system using **AWS** services such as **Lambda**, **DynamoDB**, **Cognito**, and **API Gateway**. It supports user registration, login, and logout functionality.

## Prerequisites
Before you begin, ensure that you have the following installed on your machine:

- **AWS CLI:** (configured with your AWS credentials).
- **AWS SAM CLI:** Aws serverless framework
- **Python 3.12:** (for running the Lambda functions in Python).

## Installation

1. Clone the repository:

   ```bash
    https://github.com/leopoldoromero/auth-serverless.git
    cd auth-serverless
   ```
2. Install dependencies:

    ```bash
    pip install -r requirements.txt
   ```

3. Configure AWS Credentials:

    ```bash
    aws configure
    ```
    
4. Deploy Using AWS SAM:

    ```bash
    sam build
    sam deploy --guided
    ```
5. Accessing the API Endpoints:
    After the deployment is successful, you can access the API endpoints for the login, logout, and register routes through the output shown in the deployment.
    For example, once the deployment finishes, you will see URLs like:
- **Login API:**  https://{your-api-id}.execute-api.{region}.amazonaws.com/Prod/login/
- **Logout API:**  https://{your-api-id}.execute-api.{region}.amazonaws.com/Prod/logout/
- **Register API:**  https://{your-api-id}.execute-api.{region}.amazonaws.com/Prod/register/

6. Testing Locally (Optional):
    ```bash 
    sam local invoke --event events/register-user-event.json
    ```
7. Clean Up:
      ```bash
      sam delete
      ```

