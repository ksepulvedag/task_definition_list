from time import time, sleep
import webbrowser
from boto3.session import Session
import boto3
import os
import pandas as pd

# List of AWS account IDs you want to check access to
start_url = 'https://????????.awsapps.com/start' # Change start URL
region = 'us-east-1'
accepted_roles = ['SSO-RoleName-1', 'SSO-RoleName-2', 'SSO-RoleName-3']


def configure_session(start_url):
    session = Session()
    sso_oidc = session.client('sso-oidc')
    client_creds = sso_oidc.register_client(
        clientName='ecsListTaskDefinitions',
        clientType='public',
    )
    device_authorization = sso_oidc.start_device_authorization(
        clientId=client_creds['clientId'],
        clientSecret=client_creds['clientSecret'],
        startUrl=start_url,
    )

    url = device_authorization['verificationUriComplete']
    device_code = device_authorization['deviceCode']
    expires_in = device_authorization['expiresIn']
    interval = device_authorization['interval']

    print(f"Please verify user code shown in web browser: {device_authorization['userCode']}")
    webbrowser.open(url, autoraise=True)
    for n in range(1, expires_in // interval + 1):
        sleep(interval)
        try:
            token = sso_oidc.create_token(
                grantType='urn:ietf:params:oauth:grant-type:device_code',
                deviceCode=device_code,
                clientId=client_creds['clientId'],
                clientSecret=client_creds['clientSecret'],
            )
            break
        except sso_oidc.exceptions.AuthorizationPendingException:
            pass

    return token['accessToken']


def get_accounts_ids(access_token):

    try:
        sso_client = boto3.client('sso')
        paginator = sso_client.get_paginator('list_accounts')
        
        account_ids = []
        for page in paginator.paginate(accessToken=access_token):
            for account in page['accountList']:
                new_data = {
                    'accountId': account['accountId'],
                    'accountName': account['accountName']
                }
                account_ids.append(new_data)

        return account_ids
    except Exception as e:
        print(f"Failed to list accounts. Error: {str(e)}")
        return None
    finally:
        sso_client.close()


def get_sso_credentials(access_token, account_id, accepted_roles):
    sso_client = boto3.client('sso')
    role_name = ''

    # Get list of roles for the account
    try:
        account_roles = sso_client.list_account_roles(
            accessToken=access_token,
            accountId=account_id,
        )

        for role in account_roles['roleList']:
            if role['roleName'] in accepted_roles:
                role_name = role['roleName']
                print(f"Role found {role_name} for account {account_id}")
            
        if not role_name:
            print(f"No role found for account {account_id}, check accepted_roles")
            return None
    except Exception as e:
        print(f"Failed to get list of roles for account {account_id}. Error: {str(e)}")
        return None
    finally:
        sso_client.close()

    try:
        credentials = sso_client.get_role_credentials(
            accountId=account_id,
            accessToken=access_token,
            roleName=role_name,
        )
        return credentials['roleCredentials']
    except Exception as e:
        print(f"Failed to get credentials for account {account_id}. Error: {str(e)}")
        return None
    finally:
        sso_client.close()


def list_task_definitions_in_account(session, account_id, account_name):
    try:
        ecs_client = session.client('ecs')
        response = ecs_client.list_task_definitions()
        task_definitions = response['taskDefinitionArns']

        csv_file = './list_ecs_task_definition.csv'
        columns = ['Account Name', 'Account Number', 'Arn Task Definition']

        save_task_tocsv(account_id, account_name, csv_file, columns, task_definitions)
    except Exception as e:
        print(f"Can not list task definitions in account '{account_name}' '({account_id})'. Error: {str(e)}")
    finally:
        ecs_client.close()


def save_task_tocsv(account_id, account_name, csv_file, columns, task_definitions):
        if os.path.exists(csv_file):
            header = False
        else:
            header = True

        # Validate if the response is empty
        if not task_definitions:
            mode = 'w' if header else 'a'
            task = 'No task definitions found'
            df = pd.DataFrame([[account_name, "'"+account_id, task]], columns=columns)
            df.to_csv(csv_file, encoding='utf-8', mode=mode, header=header, index=False)
            print(f"No task definitions found for '{account_name}' '({account_id})'")
            return

        for task in task_definitions:
            mode = 'w' if header else 'a'
            df = pd.DataFrame([[account_name, "'"+account_id, task]], columns=columns)
            df.to_csv(csv_file, encoding='utf-8', mode=mode, header=header, index=False)
            header = False
        print(f"Task definitions for '{account_name}' '({account_id})' saved in file '{csv_file}'")


def main():

    access_token=configure_session(start_url)
    accounts = get_accounts_ids(access_token)
    count = 1

    print(f"{len(accounts)} accounts found")

    for account in accounts:
        print(f"{count}/{len(accounts)}")
        print(f"Checking access to the account {account['accountName']} '({account['accountId']})'...")
        credentials = get_sso_credentials(access_token, account['accountId'], accepted_roles)
        if credentials:
            session = Session(
                region_name=region,
                aws_access_key_id=credentials['accessKeyId'],
                aws_secret_access_key=credentials['secretAccessKey'],
                aws_session_token=credentials['sessionToken'],
            )
            list_task_definitions_in_account(session, account['accountId'], account['accountName'])
        else:
            print(f"No access to the account {account['accountName']} '({account['accountId']})'")
        print()
        count += 1


if __name__ == "__main__":
    main()
