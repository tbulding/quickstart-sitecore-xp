#This needs to be setup to delete resources from the account owhen the stack is deleted.


#order :
# 1) AMI
# 2) ACM
# 3) Param Store

#Any secrets created
#AMI deregister & snapshot deletion
#ACM certificate removals



#SSM:
# /$stackName/cert/instance/thumbprint
# /$stackName/instance/ami/customid
# /$stackName/instance/image/custom
# /$stackName/cert/internal/acm

#Secrets manager:


#ACM:


import boto3

from botocore.exceptions import ClientError
ssm = boto3.client('ssm')
ec2 = boto3.client('ec2',region_name='eu-central-1')
ec2_resource = boto3.resource('ec2',region_name='eu-central-1')


# rootStackName = 
# ami_id_parameter = "/" + rootStackName + "/instance/ami/customid"



# def get_ssm_parameter(parameter_name):
#     response = client.get_parameter(
#         Name=parameter_name
#     )
#     return response.value
 
# def delete_ssm_parameters(parameter_list):
#     response = client.delete_parameters(
#         Names=[
#             'string',
#         ]
#     )
#     return response

ami_id = 'ami-0524f1780ecbc977b'

def ec2_deregister_ami(ami_id):
    try:
        ami_image = ec2_resource.Image(ami_id)
        response_deregister = ami_image.deregister()
        return response_deregister['ResponseMetadata']
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidAMIID.Unavailable':
            return e.response['Error']['Message']
        else:
            return e.response['Error']

def ec2_delete_ami_snaphot(deregistered_ami_id):
    list_snapshots = ec2.describe_snapshots(OwnerIds=['self'])
    all_snapshots = list_snapshots['Snapshots']
    for snapshot in all_snapshots:
        try:
            if deregistered_ami_id in snapshot['Description']:
                ec2_snapshot_id = ec2_resource.Snapshot(snapshot['SnapshotId'])
                response = ec2_snapshot_id.delete()
                return response
        except ClientError as e:
            return e.response['Error']
        else:
            return 'No matching Snapshot'

start = ec2_deregister_ami(ami_id)
try:
    if (start['HTTPStatusCode'] == '200'):
        delete_snapshot = ec2_delete_ami_snaphot(ami_id)
        print(delete_snapshot)
except:
    print(start)





# ami_id_value = get_ssm_parameter(ami_id_parameter)
# ssmparameter_list = '/$stackName/cert/instance/thumbprint', '/$stackName/instance/ami/customid'

# ami_deregister = ec2_deregister_ami(ami_id_value)