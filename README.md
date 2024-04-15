# task_definition_list

This script list all ecs task definition in all of your aws organizations accounts you have access to

It Opens web browser and authorize to boto3 generate access_token, then reads all aws accounts you have access, call ecs api "list_task_definitions", then export result to a csv file

change global vars:
start_url = your SSO start URI  
region = AWS Region  
accepted_roles = SSO role names
